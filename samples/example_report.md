# Security scan summary

**19 issues found; 7 need attention this week.**

Overall risk: **Critical**

The scan covered 4 systems. 2 critical and 5 high-risk issues should be fixed first.

## What to fix, in order

### 1. Remote Desktop is reachable

*Systems: Front desk PC, Office file server · Owner: IT / network · Effort: About a day · Findings: S-01, S-19*

**What it means.** Remote Desktop open to the internet is constantly attacked with password guessing. Found on: Front desk PC, Office file server.

**Why it matters.** Rated critical (priority 10.0/10) on a system that handles patient data.

**How to fix it**

1. Close port 3389 to the internet; require VPN plus multi-factor login for remote access.

### 2. Windows file sharing (SMB) is reachable

*Systems: Office file server · Owner: IT / network · Effort: About a day · Findings: S-02*

**What it means.** SMB exposed to the internet is one of the most common ransomware entry points. Found on: Office file server.

**Why it matters.** Rated critical (priority 10.0/10) on a system that handles patient data.

**How to fix it**

1. Block port 445 at the perimeter firewall and require VPN for remote file access.

### 3. FTP file transfer is open

*Systems: Office file server · Owner: IT / network · Effort: About a day · Findings: S-03*

**What it means.** FTP sends usernames, passwords and files unencrypted. Found on: Office file server.

**Why it matters.** Rated high (priority 9.5/10) on a system that handles patient data.

**How to fix it**

1. Replace FTP with SFTP or FTPS and close port 21.

### 4. Attackers can run scripts in visitors' browsers (cross-site scripting)

*Systems: Patient portal · Owner: Web developer · Effort: About a day · Findings: S-04*

**What it means.** Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. Found on: Patient portal.

**Why it matters.** Rated high (priority 9.5/10) on a system that handles patient data.

**How to fix it**

1. Encode user input before displaying it and add a Content Security Policy.

### 5. Database queries can be manipulated (SQL injection)

*Systems: Patient portal · Owner: Web developer · Effort: About a day · Findings: S-05*

**What it means.** SQL injection may be possible. Found on: Patient portal.

**Why it matters.** Rated high (priority 9.5/10) on a system that handles patient data.

**How to fix it**

1. Use parameterized queries for every database call that includes user input.

### 6. Redis cache is reachable

*Systems: Billing database · Owner: IT / network · Effort: About a day · Findings: S-06*

**What it means.** Redis has no login by default, so anyone who can reach it can read or change data. Found on: Billing database.

**Why it matters.** Rated high (priority 8.0/10) on a system that handles patient data.

**How to fix it**

1. Bind Redis to localhost, enable requirepass and firewall port 6379.

### 7. VNC screen sharing is open

*Systems: Front desk PC · Owner: IT / network · Effort: About a day · Findings: S-10*

**What it means.** VNC often has weak or no passwords and gives full control of the screen. Found on: Front desk PC.

**Why it matters.** Rated high (priority 7.0/10).

**How to fix it**

1. Remove VNC or put it behind VPN with strong authentication.

### 8. No Content Security Policy

*Systems: Patient portal · Owner: Web developer · Effort: Under an hour · Findings: S-07*

**What it means.** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Found on: Patient portal.

**Why it matters.** Rated medium (priority 7.5/10) on a system that handles patient data.

**How to fix it**

1. Add a Content-Security-Policy header that allows only your own scripts.

## Quick wins

- Add a Content-Security-Policy header that allows only your own scripts.

## Questions for you

- Which of these systems are supposed to be reachable from the internet?

## Appendix: all findings

| ID | Score | Severity | System | Issue | Related HIPAA safeguard |
|---|---|---|---|---|---|
| S-01 | 10.0 | critical | Office file server | Remote Desktop is reachable | 164.312(d) Person or entity authentication |
| S-02 | 10.0 | critical | Office file server | Windows file sharing (SMB) is reachable | 164.312(a)(1) Access control |
| S-03 | 9.5 | high | Office file server | FTP file transfer is open | 164.312(e)(1) Transmission security |
| S-04 | 9.5 | high | Patient portal | Attackers can run scripts in visitors' browsers (cross-site scripting) | 164.312(c)(1) Integrity |
| S-05 | 9.5 | high | Patient portal | Database queries can be manipulated (SQL injection) | 164.312(c)(1) Integrity |
| S-06 | 8.0 | high | Billing database | Redis cache is reachable | 164.312(a)(1) Access control |
| S-07 | 7.5 | medium | Patient portal | No Content Security Policy | 164.312(c)(1) Integrity |
| S-08 | 7.5 | medium | Patient portal | Pages can be embedded by other sites (clickjacking) | 164.312(c)(1) Integrity |
| S-09 | 7.5 | medium | Patient portal | Unencrypted web traffic is accepted | 164.312(e)(1) Transmission security |
| S-10 | 7.0 | high | Front desk PC | VNC screen sharing is open | 164.312(d) Person or entity authentication |
| S-11 | 6.5 | medium | Patient portal | Forms can be submitted from other websites (missing CSRF protection) | 164.312(c)(1) Integrity |
| S-12 | 6.0 | medium | Billing database | PostgreSQL database is reachable | 164.312(a)(1) Access control |
| S-13 | 5.5 | low | Patient portal | Browsers aren't told to always use HTTPS (no HSTS) | 164.312(e)(1) Transmission security |
| S-14 | 5.5 | low | Patient portal | Browsers may guess file types (missing nosniff header) | — |
| S-15 | 5.5 | low | Patient portal | Login cookies can be read by page scripts | 164.312(a)(1) Access control |
| S-16 | 5.5 | low | Patient portal | Login cookies can be sent over unencrypted connections | 164.312(e)(1) Transmission security |
| S-17 | 5.5 | low | Patient portal | SSH remote administration is open | 164.312(d) Person or entity authentication |
| S-18 | 5.5 | low | Patient portal | Server software version is advertised | — |
| S-19 | 5.0 | medium | Front desk PC | Remote Desktop is reachable | 164.312(d) Person or entity authentication |
| S-20 | 1.0 | info | Billing database | SSH remote administration is open | 164.312(d) Person or entity authentication |
| S-21 | 1.0 | info | Front desk PC | Port 9100 is open (jetdirect) | — |
| S-22 | 1.0 | info | Patient portal | HTTPS web service | — |

<sub>Generated by ScanBrief (offline template). HIPAA references are a starting point for discussion, not a compliance determination.</sub>
