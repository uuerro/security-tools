So I built this as part of my journey into cybersecurity — I'm 18, just finished the Google Cybersecurity Certificate, and instead of just studying theory I wanted to actually build the tools I was learning about. Everything in here came from real hands-on lab work, not tutorials I copy pasted.
uero.py — Automated Log Threat Analyzer
This one I'm most proud of honestly. Uero reads Linux auth logs and automatically finds what would take an analyst 30 minutes to find manually. I built it after doing a SOC simulation lab where I had to investigate a real attack hidden in log data — brute force, impossible travel, reverse shell and all. So I figured why not automate it.
What it detects:

Brute force attacks — flags any IP hammering failed logins past a threshold
Successful logins after brute force — meaning the attack actually worked
Impossible travel — same account logging in from internal and external IPs in a short window
Privilege escalation — dangerous sudo commands like reading /etc/shadow or opening reverse shells
Full IOC extraction — pulls every malicious IP and compromised account into a clean summary


port_scanner.py — TCP Port Scanner
Built this one first. It probes a target IP across the ports that actually matter in security work and tells you what's open and what service is running there. Simple but it does exactly what nmap does at its core — I just wanted to understand how it works under the hood before relying on the tool.
python3 port_scanner.py

Still building. Uero is getting a web dashboard and eventually AI-powered report generation. More tools coming as I keep learning.
