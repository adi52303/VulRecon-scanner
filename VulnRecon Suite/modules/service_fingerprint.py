# modules/service_fingerprint.py
import re

def parse_server_header(http_headers: dict) -> list[str]:
    """
    Extract product/version-like tokens from HTTP 'Server' header.
    Returns a list of strings to query CVEs (e.g., ['Apache 2.4.6','Apache/2.4.6']).
    """
    if not http_headers:
        return []
    server = http_headers.get("Server") or http_headers.get("server") or ""
    if not server:
        return []

    # Common forms: "Apache/2.4.6 (CentOS)", "nginx/1.18.0", "Microsoft-IIS/10.0"
    m = re.search(r"([A-Za-z][A-Za-z\-\s]+?)[/ ](\d+(?:\.\d+){0,3})", server)
    if not m:
        # Fallback: return the raw chunk for keyword search
        return [server.strip()]

    product = m.group(1).strip().replace("-", " ")
    version = m.group(2).strip()

    # Return a couple of search variants
    return [f"{product} {version}", f"{product}/{version}"]
