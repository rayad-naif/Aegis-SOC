import socket
import ssl
import http.client
import subprocess
import platform
import re

def detect_os(ip):
    """
    Tactical OS Fingerprinting via ICMP TTL Analysis.
    Predicts the target OS based on the Time-To-Live (TTL) value.
    - Linux/Unix: ~64
    - Windows: ~128
    - Network Infrastructure: ~255
    """
    try:
        # Determine ping parameter based on current platform
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        # Execute a single ping to capture the TTL response
        output = subprocess.check_output(['ping', param, '1', ip], stderr=subprocess.STDOUT, timeout=2).decode()
        
        # Regex to extract the TTL value
        ttl_match = re.search(r"ttl=(\d+)", output.lower())
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64: return f"Linux / Unix (TTL: {ttl})"
            if ttl <= 128: return f"MS Windows (TTL: {ttl})"
            if ttl <= 255: return f"Network Infrastructure (TTL: {ttl})"
        
        return "Unknown OS (Filtered/Shielded)"
    except:
        return "Detection Shielded (ICMP Blocked)"

def audit_ssl(hostname):
    """
    Performs a live TLS handshake to identify protocol versions 
    and cryptographic cipher suites.
    """
    try:
        context = ssl.create_default_context()
        # Create a connection to the HTTPS port
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
        # Case-insensitive header dictionary
        headers = {k.lower(): v for k, v in res.getheaders()}
        
        # Comprehensive list of security-critical headers
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