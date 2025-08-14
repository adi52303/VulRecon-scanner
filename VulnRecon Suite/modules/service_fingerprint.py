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

    
    m = re.search(r"([A-Za-z][A-Za-z\-\s]+?)[/ ](\d+(?:\.\d+){0,3})", server)
    if not m:
        
        return [server.strip()]

    product = m.group(1).strip().replace("-", " ")
    version = m.group(2).strip()

    
    return [f"{product} {version}", f"{product}/{version}"]
