# 🛡️ Sentinel Security Console

A single-page Streamlit cybersecurity workstation with three advanced modules:

1. **Threat Scanner** — heuristic IoC scanner matching 8 signatures (hardcoded creds, AWS keys, JWTs, XSS, SQLi, dangerous calls, IPs, API secrets) with severity-weighted risk scoring.
2. **Password Forge** — CSPRNG-backed (`secrets`) credential generator with entropy analysis and brute-force time estimation.
3. **Attack Surface Map** — interactive topology of nodes with exposure levels, patch actions, and aggregate lateral-risk metrics.

A shared **Posture Score** in the sidebar updates live as you scan, forge, and patch.

## Run
