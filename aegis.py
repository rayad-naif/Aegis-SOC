import socket
import ssl
import http.client

def audit_ssl(hostname):
    """Performs a deep SSL/TLS handshake audit."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return {"status": "Secure", "protocol": ssock.version(), "cipher": ssock.cipher()[0]}
    except:
        return {"status": "Insecure", "protocol": "N/A", "cipher": "None"}

def audit_headers(target):
    """Audits HTTP security headers for hardening."""
    try:
        conn = http.client.HTTPConnection(target, timeout=2)
        conn.request("HEAD", "/")
        res = conn.getresponse()
        headers = {k.lower(): v for k, v in res.getheaders()}
        check = []
        for h in ["x-frame-options", "content-security-policy", "strict-transport-security"]:
            check.append({"header": h, "status": "SECURE" if h in headers else "MISSING"})
        return check
    except:
        return []
