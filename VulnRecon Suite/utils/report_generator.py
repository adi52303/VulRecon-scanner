import json
import os
from datetime import datetime

def save_report(domain, whois_data, dns_data, subdomains_data, port_data, http_headers=None, cve_by_software=None, basic_risks=None):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    txt_filename = f"reports/scan_report_{domain}_{timestamp}.txt"
    json_filename = f"reports/scan_report_{domain}_{timestamp}.json"

    def clean_date(date_value):
        if isinstance(date_value, list):
            return [str(d) for d in date_value]
        return str(date_value) if date_value else "N/A"

    total_open_ports = sum(len(ports) for ports in port_data.values())
    total_subdomains = len(subdomains_data) if subdomains_data else 0
    total_dns_records = sum(len(v) for v in dns_data.values()) if isinstance(dns_data, dict) else 0

    with open(txt_filename, "w", encoding="utf-8") as f:
        f.write("========================================\n")
        f.write(" Vulrecon Suite Report\n")
        f.write(f" Target: {domain}\n")
        f.write(f" Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("========================================\n\n")

        # Summary
        f.write("[Summary]\n")
        f.write(f"- Target: {domain}\n")
        f.write(f"- Total Open Ports: {total_open_ports}\n")
        f.write(f"- Services Found: {', '.join({svc for ports in port_data.values() for svc in [{21: 'FTP', 22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL'}.get(p, 'Unknown') for p in ports]})}\n")
        f.write(f"- DNS Records Found: {total_dns_records}\n")
        f.write(f"- Subdomains Found: {total_subdomains}\n\n")

        # WHOIS
        f.write("[1] WHOIS Information\n")
        f.write("---------------------\n")
        if isinstance(whois_data, dict):
            f.write(f"Domain Name: {whois_data.get('domain_name', 'N/A')}\n")
            f.write(f"Registrar: {whois_data.get('registrar', 'N/A')}\n")
            f.write(f"Registrar URL: {whois_data.get('registrar_url', 'N/A')}\n")
            f.write(f"Creation Date: {clean_date(whois_data.get('creation_date'))}\n")
            f.write(f"Expiration Date: {clean_date(whois_data.get('expiration_date'))}\n")
            f.write(f"Updated Date: {clean_date(whois_data.get('updated_date'))}\n")
            f.write("Name Servers:\n")
            for ns in whois_data.get("name_servers", []):
                f.write(f"  - {ns}\n")
            f.write(f"Contact Email: {whois_data.get('emails', 'N/A')}\n")
            f.write(f"Country: {whois_data.get('country', 'N/A')}\n\n")
        else:
            f.write(str(whois_data) + "\n\n")

        # DNS
        f.write("[2] DNS Records\n")
        f.write("---------------\n")
        if isinstance(dns_data, dict):
            for record in dns_data.get("A", []):
                f.write(f"A Record: {record}\n")
            for mx in dns_data.get("MX", []):
                f.write(f"MX Record: {mx}\n")
            for ns in dns_data.get("NS", []):
                f.write(f"NS Record: {ns}\n")
        else:
            f.write(str(dns_data) + "\n")
        f.write("\n")

        # Subdomains
        f.write("[3] Subdomain Enumeration\n")
        f.write("-------------------------\n")
        if subdomains_data:
            for sub, ip in subdomains_data.items():
                f.write(f"{sub} -> {ip}\n")
        else:
            f.write("No subdomains found.\n")
        f.write("\n")

        # Ports
        f.write("[4] Open Ports\n")
        f.write("--------------\n")
        for host, ports in port_data.items():
            f.write(f"Target: {host}\n")
            for port in ports:
                service_name = {
                    21: "FTP",
                    22: "SSH",
                    23: "Telnet",
                    80: "HTTP",
                    443: "HTTPS",
                    3306: "MySQL"
                }.get(port, "Unknown Service")
                f.write(f"  - {port} ({service_name})\n")
        f.write("\n")

        # HTTP Headers
        f.write("[5] HTTP Headers\n")
        f.write("----------------\n")
        if http_headers:
            for key, value in http_headers.items():
                f.write(f"{key}: {value}\n")
        else:
            f.write("No HTTP headers collected.\n")
        f.write("\n")

        # [6] Known Vulnerabilities (from CVE database)
        f.write("[6] Known Vulnerabilities (CVE)\n")
        f.write("--------------------------------\n")
        if cve_by_software:
            for soft, cves in cve_by_software.items():
                f.write(f"{soft}:\n")
                for c in cves:
                    sev = c.get('severity') or "N/A"
                    score = c.get('score')
                    score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "N/A"
                    f.write(f"  - {c['cve_id']} | Sev: {sev} | Score: {score_str}\n")
                    f.write(f"    {c['description'][:220]}{'...' if len(c['description'])>220 else ''}\n")
                    f.write(f"    Ref: {c['url']}\n")
        else:
            f.write("No CVEs matched detected software.\n")
        f.write("\n")


        # Risks
        f.write("[Potential Risks]\n")
        f.write("-----------------\n")
        risks = {
            21: "FTP may allow anonymous login or use outdated encryption.",
            22: "SSH could be vulnerable if weak credentials are used.",
            23: "Telnet sends data in plain text, insecure for sensitive info.",
            80: "HTTP could expose the site to web-based attacks (XSS, SQLi).",
            443: "HTTPS may have weak TLS/SSL configurations.",
            3306: "MySQL could be targeted for database attacks if exposed."
        }
        for host, ports in port_data.items():
            for port in ports:
                if port in risks:
                    f.write(f"- Port {port}: {risks[port]}\n")
        f.write("\n")

        f.write("========================================\n")
        f.write("End of Report\n")
        f.write("Generated by: Vulrecon Suite v1.0\n")

    # JSON version
    json_data = {
        "target": domain,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_open_ports": total_open_ports,
            "services_found": list({svc for ports in port_data.values() for svc in [{21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 3306: "MySQL"}.get(p, "Unknown") for p in ports]}),
            "dns_records_found": total_dns_records,
            "subdomains_found": total_subdomains
        },
        "whois": whois_data if isinstance(whois_data, dict) else {"raw": str(whois_data)},
        "dns_records": dns_data if isinstance(dns_data, dict) else {"raw": str(dns_data)},
        "subdomains": subdomains_data or {},
        "open_ports": port_data,
        "http_headers": http_headers or {},
        "risks": {str(port): risks.get(port, "Unknown risk") for host, ports in port_data.items() for port in ports}
    }

    with open(json_filename, "w", encoding="utf-8") as jf:
        json.dump(json_data, jf, indent=4)

    print(f"\n[+] Report saved as: {txt_filename}")
    print(f"[+] JSON data saved as: {json_filename}")
