import socket
import ssl
import http.client
import subprocess
import platform
import re
from urllib.parse import urlparse

# Modern User-Agent to bypass WAF (Cloudflare/Akamai) bot blocks
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

def detect_os(ip):
    """
    Tactical OS Fingerprinting with Firewall & CDN detection.
    1. ICMP TTL Analysis (Active)
    2. TCP Banner Grabbing (Passive Fallback)
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

    # Phase 2: HTTP Banner Analysis (Passive)
    try:
        conn = http.client.HTTPConnection(ip, timeout=2)
        conn.request("HEAD", "/", headers={"User-Agent": USER_AGENT})
        res = conn.getresponse()
        server = res.getheader("Server", "").lower()
        
        if "cloudflare" in server: return "Cloud Infrastructure (Cloudflare WAF)"
        if "akamai" in server: return "Cloud Infrastructure (Akamai CDN)"
        if any(x in server for x in ["iis", "microsoft"]): return "MS Windows (via HTTP Banner)"
        if any(x in server for x in ["ubuntu", "debian", "nginx", "apache"]): return "Linux (via HTTP Banner)"
        
        if server: return f"Unknown OS (Header: {server})"
    except:
        pass

    return "Detection Shielded (Firewall Active)"

def audit_ssl(hostname):
    """Performs TLS handshake to identify protocol and cipher suites."""
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

def audit_headers(target, path="/", depth=0):
    """
    Deep Header Audit with Redirect Following.
    Fixes the 'All Headers Missing' issue by following 301/302 redirects
    and using a realistic User-Agent.
    """
    if depth > 3: return [] # Prevent redirect loops

    try:
        # Use HTTPS if possible, fallback to HTTP
        conn = http.client.HTTPSConnection(target, timeout=3)
        conn.request("GET", path, headers={"User-Agent": USER_AGENT})
        res = conn.getresponse()
        
        # Handle Redirects (Fixes missing headers on landing pages)
        if res.status in [301, 302]:
            location = res.getheader("Location")
            if location:
                parsed = urlparse(location)
                new_host = parsed.netloc if parsed.netloc else target
                new_path = parsed.path if parsed.path else "/"
                return audit_headers(new_host, new_path, depth + 1)

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
        
        return [{"header": label, "status": "SECURE" if h_key in headers else "MISSING"} for h_key, label in checks]
    except Exception:
        # Fallback to HTTP if HTTPS fails
        try:
            conn = http.client.HTTPConnection(target, timeout=3)
            conn.request("GET", path, headers={"User-Agent": USER_AGENT})
            res = conn.getresponse()
            headers = {k.lower(): v for k, v in res.getheaders()}
            return [{"header": label, "status": "SECURE" if h_key in headers else "MISSING"} for h_key, label in checks]
        except:
            return []
