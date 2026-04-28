# Cybersecurity_Intern-Task
CyberShield V3: Advanced Security Portal

Internship Project: Weeks 4, 5, and 6 Intern: Syed Zunair Hussain Environment: Kali Linux / Node.js

PROJECT OVERVIEW

This repository documents the transition from a vulnerable legacy system to a hardened architecture. The project involves intrusion detection, manual and automated exploitation testing, security auditing, and secure deployment practices.

WEEK 4: ADVANCED THREAT DETECTION AND HARDENING

Objective: Build a defensive perimeter to mitigate automated attacks and unauthorized scripts.

Intrusion Detection (Fail2Ban): Configured a filter to monitor security.log for failed login attempts.

Rule: 5 failed attempts within 2 minutes results in a 10-minute IP ban.

API Hardening (Rate Limiting): Implemented express-rate-limit to stop brute-force scripts.

Logic: 10 attempts allowed per 10 minutes per IP.

Security Headers and CSP: Integrated Helmet.js for HSTS and implemented a Nonce-based CSP for Tailwind CSS to prevent XSS.

WEEK 5: ETHICAL HACKING AND VULNERABILITY MITIGATION

Objective: Act as an attacker to verify defenses and patch high-priority vulnerabilities.

Reconnaissance: * nmap -sV localhost -p 3000 (Verified port status)

Used Nikto to identify missing headers.

SQL Injection (SQLi) Exploitation: * Tool: sqlmap -u "http://localhost:3000/api/login-vulnerable" --data "email=test@test.com&password=123" --method POST --batch --dbs

Fix: Migrated to Prepared Statements: db.get("SELECT * FROM users WHERE email = ?", [email], ...)

CSRF Protection: Implemented csurf. Verified with Burp Suite (403 Forbidden on missing token).

WEEK 6: AUDITS AND SECURE DEPLOYMENT

Objective: Implement a Secure Software Development Life Cycle (SSDLC).

Automated Assessment (OWASP ZAP): Flagged SQLi as CRITICAL; verified Winston real-time logging.

Dependency Scanning (Snyk):

npx snyk test

npx snyk monitor

Remediation: Updated bcrypt and inflight to resolve critical vulnerabilities.

Docker Hardening: Migrated to node:18-slim.

docker build -t cybersec-app:v2 .

sudo npx snyk container test cybersec-app:v2

Result: 0 Critical / 0 High vulnerabilities.

OWASP TOP 10 COMPLIANCE SUMMARY

A01:2021-Broken Access Control: JWT validation & CORS.

A02:2021-Cryptographic Failures: Bcrypt (10 salt rounds).

A03:2021-Injection: Parameterized Queries.

A04:2021-Insecure Design: CSRF Middleware.

A05:2021-Security Misconfiguration: Helmet.js headers.

A09:2021-Security Logging: Winston persistent auditing.

video link for proof: https://drive.google.com/file/d/10TCNoVFVAjZvuB08ZrAHyBxgydn3dXp9/view?usp=sharing

INSTALLATION AND SETUP

git clone [URL] npm install npx snyk test node app.js tail -f security.log
