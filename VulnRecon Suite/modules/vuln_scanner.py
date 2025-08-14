# modules/vuln_scanner.py
from modules.cve_lookup import fetch_cves

def basic_risk_rules(open_ports: list[int]) -> list[dict]:
    findings = []
    if 21 in open_ports:
        findings.append({"port": 21, "service": "FTP", "severity": "High",
                         "issue": "FTP may allow anonymous login or weak encryption.",
                         "recommendation": "Disable anonymous login; prefer SFTP/FTPS."})
    if 22 in open_ports:
        findings.append({"port": 22, "service": "SSH", "severity": "Medium",
                         "issue": "SSH may permit weak auth or legacy ciphers.",
                         "recommendation": "Key-based auth, disable root login, strong ciphers."})
    if 80 in open_ports:
        findings.append({"port": 80, "service": "HTTP", "severity": "Medium",
                         "issue": "Unencrypted HTTP traffic.",
                         "recommendation": "Redirect to HTTPS; HSTS."})
    if 443 in open_ports:
        findings.append({"port": 443, "service": "HTTPS", "severity": "Low",
                         "issue": "Verify TLS config and headers.",
                         "recommendation": "Enforce TLS 1.2+, modern ciphers, security headers."})
    return findings

def cve_findings_from_software(software_tokens: list[str], max_per_software: int = 6) -> dict[str, list[dict]]:
    """
    For each token like 'Apache 2.4.6', fetch top CVEs.
    Returns: { 'Apache 2.4.6': [ {cve_id, severity, score, description, url}, ...], ... }
    """
    results = {}
    seen_ids = set()
    for token in software_tokens:
        cves = fetch_cves(token, max_results=max_per_software)
        dedup = []
        for c in cves:
            if c["cve_id"] and c["cve_id"] not in seen_ids:
                dedup.append(c)
                seen_ids.add(c["cve_id"])
        if dedup:
            results[token] = dedup
    return results
