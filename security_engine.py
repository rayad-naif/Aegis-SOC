import socket
import ssl
import http.client
import subprocess
import platform
import re

def detect_os(ip):
    """
    Tactical OS Fingerprinting with Firewall and CDN/WAF Detection.
    1. Attempts ICMP TTL Analysis (Active).
    2. Falls back to HTTP Banner Analysis (Passive) if ICMP is blocked.
    3. Identifies Cloud Infrastructure (Cloudflare, etc.) to explain masking.
    """
    # Phase 1: ICMP TTL Analysis
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        output = subprocess.check_output(['ping', param, '1', ip], stderr=subprocess.STDOUT, timeout=2).decode()
        
        ttl_match = re.search(r"ttl=(\d+)", output.lower())
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64: return f"Linux / Unix (TTL: {ttl})"
            if ttl <= 128: return f"MS Windows (TTL: {ttl})"
            if ttl <= 255: return f"Network Infrastructure (TTL: {ttl})"
    except Exception:
        pass

    # Phase 2: HTTP Banner Grabbing (TCP Fallback)
    try:
        conn = http.client.HTTPConnection(ip, timeout=2)
        conn.request("HEAD", "/")
        res = conn.getresponse()
        server_header = res.getheader("Server", "").lower()
        
        # Detect Cloud Masking (WAF/CDN)
        if "cloudflare" in server_header:
            return "Cloud Infrastructure (Cloudflare WAF)"
        if any(x in server_header for x in ["akamai", "amazons3", "awselb", "cloudfront"]):
            return "Cloud Infrastructure (CDN/LB Masked)"

        # Detect OS via specific Banners
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
        return []
