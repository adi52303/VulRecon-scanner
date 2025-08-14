from modules.whois_lookup import whois_lookup
from modules.dns_lookup import dns_lookup
from modules.port_scanner import port_scan
from modules.subdomain_bruteforce import subdomain_bruteforce
from modules.detect_wildcard import detect_wildcard

from utils.report_generator import save_report


from modules.http_header_grabber import grab_http_headers
from modules.service_fingerprint import parse_server_header
from modules.vuln_scanner import basic_risk_rules, cve_findings_from_software

import socket

if __name__ == "__main__":
    target = input("Enter target IP or domain: ")

    # WHOIS Lookup
    whois_data = whois_lookup(target)

    # DNS Lookup
    dns_data = dns_lookup(target)

    # HTTP Headers
    http_headers = grab_http_headers(target)

    # Wildcard DNS detection
    wildcard_ips = detect_wildcard(target)

    # Subdomain Brute Force
    subdomains_data = subdomain_bruteforce(target, wildcard_ips)

    # Port Scan
    port_scan_results = {}
    try:
        main_ip = socket.gethostbyname(target)
        port_scan_results[target] = port_scan(main_ip)
    except Exception as e:
        print(f"[!] Failed to resolve {target}: {e}")

    for sub, ips in subdomains_data:
        for ip in ips:
            port_scan_results[sub] = port_scan(ip)

    http_headers = grab_http_headers(target)

# Port scan (you already do this)
open_ports_main = port_scan_results.get(target, [])

# === NEW: build software list & fetch CVEs ===
software_tokens = parse_server_header(http_headers)  # e.g., ['Apache 2.4.6','Apache/2.4.6']
cve_by_software = cve_findings_from_software(software_tokens, max_per_software=6)

# You may also merge 'basic_risk_rules' into your TXT/JSON report if you want a separate section:
basic_risks = basic_risk_rules(set(open_ports_main))  # expects list[int] or set[int]

# Finally include CVEs in save_report:
save_report(
    target,
    whois_data,
    dns_data,
    subdomains_data,
    port_scan_results,
    http_headers=http_headers,
    cve_by_software=cve_by_software,
    basic_risks=basic_risks
)