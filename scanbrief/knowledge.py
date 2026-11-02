"""Curated rules that turn raw scanner output into severities and fixes.

HIPAA references point to the related Security Rule technical safeguard
(45 CFR 164.312). They are a starting point for a compliance conversation,
not a compliance determination.
"""

from __future__ import annotations

ACCESS = "164.312(a)(1) Access control"
AUDIT = "164.312(b) Audit controls"
INTEGRITY = "164.312(c)(1) Integrity"
AUTH = "164.312(d) Person or entity authentication"
TRANSMISSION = "164.312(e)(1) Transmission security"

# port -> (title, severity if internet-facing, severity if internal, detail, fix, safeguard)
PORT_RULES: dict[int, tuple[str, str, str, str, str, str | None]] = {
    21: ("FTP file transfer is open", "high", "medium",
         "FTP sends usernames, passwords and files unencrypted.",
         "Replace FTP with SFTP or FTPS and close port 21.", TRANSMISSION),
    23: ("Telnet remote login is open", "critical", "high",
         "Telnet sends every keystroke, including passwords, in clear text.",
         "Disable Telnet and use SSH with key-based login.", TRANSMISSION),
    80: ("Unencrypted web traffic is accepted", "medium", "low",
         "The site answers on plain HTTP, so data can be read or altered in transit.",
         "Redirect all HTTP requests to HTTPS and enable HSTS.", TRANSMISSION),
    139: ("Windows file sharing (NetBIOS) is reachable", "high", "medium",
          "Legacy Windows file sharing is a frequent target for ransomware.",
          "Block ports 139 and 445 at the firewall for anything outside the office network.", ACCESS),
    445: ("Windows file sharing (SMB) is reachable", "critical", "medium",
          "SMB exposed to the internet is one of the most common ransomware entry points.",
          "Block port 445 at the perimeter firewall and require VPN for remote file access.", ACCESS),
    1433: ("SQL Server database is reachable", "critical", "medium",
           "The database accepts connections directly instead of only through the application.",
           "Restrict port 1433 to the application servers that need it.", ACCESS),
    3306: ("MySQL database is reachable", "critical", "medium",
           "The database accepts connections directly instead of only through the application.",
           "Bind MySQL to localhost or restrict port 3306 to the app server.", ACCESS),
    3389: ("Remote Desktop is reachable", "critical", "medium",
           "Remote Desktop open to the internet is constantly attacked with password guessing.",
           "Close port 3389 to the internet; require VPN plus multi-factor login for remote access.", AUTH),
    5432: ("PostgreSQL database is reachable", "critical", "medium",
           "The database accepts connections directly instead of only through the application.",
           "Restrict port 5432 to the application servers in pg_hba.conf and the firewall.", ACCESS),
    5900: ("VNC screen sharing is open", "critical", "high",
           "VNC often has weak or no passwords and gives full control of the screen.",
           "Remove VNC or put it behind VPN with strong authentication.", AUTH),
    6379: ("Redis cache is reachable", "critical", "high",
           "Redis has no login by default, so anyone who can reach it can read or change data.",
           "Bind Redis to localhost, enable requirepass and firewall port 6379.", ACCESS),
    27017: ("MongoDB database is reachable", "critical", "high",
            "Exposed MongoDB servers are routinely found and wiped by automated attacks.",
            "Enable authentication and restrict port 27017 to the app servers.", ACCESS),
    22: ("SSH remote administration is open", "low", "info",
         "SSH is encrypted, but an internet-facing login is still guessed at constantly.",
         "Allow key-based login only, disable root login, and limit source IPs if possible.", AUTH),
    443: ("HTTPS web service", "info", "info",
          "Encrypted web traffic. Expected for a public site.",
          "No action needed beyond keeping TLS settings current.", None),
}

# ZAP pluginid -> (plain title, fix, safeguard). Severity comes from ZAP's own riskcode.
ZAP_RULES: dict[str, tuple[str, str, str | None]] = {
    "40018": ("Database queries can be manipulated (SQL injection)",
              "Use parameterized queries for every database call that includes user input.", INTEGRITY),
    "40012": ("Attackers can run scripts in visitors' browsers (cross-site scripting)",
              "Encode user input before displaying it and add a Content Security Policy.", INTEGRITY),
    "10202": ("Forms can be submitted from other websites (missing CSRF protection)",
              "Add anti-CSRF tokens to every form that changes data.", INTEGRITY),
    "10035": ("Browsers aren't told to always use HTTPS (no HSTS)",
              "Send the Strict-Transport-Security header on every HTTPS response.", TRANSMISSION),
    "10011": ("Login cookies can be sent over unencrypted connections",
              "Set the Secure flag on all session cookies.", TRANSMISSION),
    "10010": ("Login cookies can be read by page scripts",
              "Set the HttpOnly flag on session cookies.", ACCESS),
    "10038": ("No Content Security Policy",
              "Add a Content-Security-Policy header that allows only your own scripts.", INTEGRITY),
    "10020": ("Pages can be embedded by other sites (clickjacking)",
              "Send X-Frame-Options: DENY or a CSP frame-ancestors rule.", INTEGRITY),
    "10021": ("Browsers may guess file types (missing nosniff header)",
              "Send X-Content-Type-Options: nosniff.", None),
    "10036": ("Server software version is advertised",
              "Hide the version in the Server header so attackers can't target known bugs.", None),
}
