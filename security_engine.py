import socket
import ssl
import http.client
import subprocess
import platform
import re

def detect_os(ip):
    """
    Tactical OS Fingerprinting with Firewall Fallback.
    1. Attempts ICMP TTL Analysis (Active).
    2. Falls back to HTTP Banner Analysis (Passive) if ICMP is blocked.
    """
    # Phase 1: ICMP TTL Analysis
    try:
        # Determine ping parameter based on local OS
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        # Send a single probe
        output = subprocess.check_output(['ping', param, '1', ip], stderr=subprocess.STDOUT, timeout=2).decode()
        
        ttl_match = re.search(r"ttl=(\d+)", output.lower())
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64: return f"Linux / Unix (TTL: {ttl})"
            if ttl <= 128: return f"MS Windows (TTL: {ttl})"
            if ttl <= 255: return f"Network Infrastructure (TTL: {ttl})"
    except Exception:
        # ICMP Blocked by Firewall - Proceed to Phase 2 (Banner Grabbing)
        pass

    # Phase 2: HTTP Banner Grabbing (TCP Fallback)
    # Firewalls often allow Port 80/443 even if they block Ping.
    try:
        # Attempt to grab header from port 80
        conn = http.client.HTTPConnection(ip, timeout=2)
        conn.request("HEAD", "/")
        res = conn.getresponse()
        server_header = res.getheader("Server", "").lower()
        
        if any(x in server_header for x in ["ubuntu", "debian", "apache", "nginx"]):
            return "Linux (via HTTP Banner)"
        if any(x in server_header for x in ["iis", "microsoft", "win64"]):
            return "MS Windows (via HTTP Banner)"
            
        if server_header:
            return f"Unknown OS (Header: {server_header})"
    except Exception:
        pass

    return "Detection Shielded (Firewall Active)"

def audit_ssl(hostname):
    """
    Performs a live TLS handshake to identify protocol versions 
    and cryptographic cipher suites.
    """
    try:
        context = ssl.create_default_context()
        # Set short timeout for responsive scanning
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return {
                    "status": "Secure",
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher()[0]
                }
    except Exception:
        return {"status": "Insecure/Legacy", "protocol": "N/A", "cipher": "None"}

def audit_headers(target):
    """
    Deep Header Audit for 8+ Security Protocols.
    Checks for presence of hardening headers to map vulnerability surface.
    """
    try:
        conn = http.client.HTTPConnection(target, timeout=3)
        conn.request("HEAD", "/")
        res = conn.getresponse()
        headers = {k.lower(): v for k, v in res.getheaders()}
        
        checks = [
            ("content-security-policy", "CSP"),
            ("strict-transport-security", "HSTS"),
            ("x-frame-options", "X-Frame-Options"),
            ("x-content-type-options", "X-Content-Type"),
            ("referrer-policy", "Referrer-Policy"),
            ("permissions-policy", "Permissions-Policy"),
            ("x-xss-protection", "X-XSS-Protection"),
            ("expect-ct", "Expect-CT")
        ]
        
        audit_results = []
        for h_key, label in checks:
            status = "SECURE" if h_key in headers else "MISSING"
            audit_results.append({"header": label, "status": status})
            
        return audit_results
    except Exception:
        # Return empty list on connection failure
        return []
