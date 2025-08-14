import socket
import requests
import whois
import dns.resolver
import random
import string
from datetime import datetime
import os

# ======================
# BASIC FUNCTIONS
# ======================

def basic_port_scan(target, ports=None):
    if ports is None:
        ports = [21, 22, 23, 80, 443, 3306]
    print(f"\n[+] Scanning {target}...\n")
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"[OPEN] Port {port}")
            open_ports.append(port)
        else:
            print(f"[CLOSED] Port {port}")
        sock.close()
    return open_ports


def whois_lookup(domain):
    try:
        data = whois.whois(domain)
        return {
            "domain_name": data.domain_name if isinstance(data.domain_name, str) else (data.domain_name[0] if data.domain_name else "N/A"),
            "registrar": data.registrar or "N/A",
            "registrar_url": getattr(data, "registrar_url", "N/A"),
            "creation_date": str(data.creation_date) if data.creation_date else "N/A",
            "expiration_date": str(data.expiration_date) if data.expiration_date else "N/A",
            "updated_date": str(data.updated_date) if data.updated_date else "N/A",
            "name_servers": list(data.name_servers) if data.name_servers else [],
            "emails": data.emails if data.emails else "N/A",
            "country": getattr(data, "country", "N/A")
        }
    except Exception:
        return {
            "domain_name": "Error",
            "registrar": "Error",
            "registrar_url": "Error",
            "creation_date": "Error",
            "expiration_date": "Error",
            "updated_date": "Error",
            "name_servers": [],
            "emails": "Error",
            "country": "Error"
        }



def dns_lookup(domain):
    dns_data = {"A": [], "MX": [], "NS": []}

    try:
        # A records
        try:
            for rdata in dns.resolver.resolve(domain, 'A'):
                dns_data["A"].append(rdata.address)
        except:
            pass

        # MX records
        try:
            for rdata in dns.resolver.resolve(domain, 'MX'):
                dns_data["MX"].append(str(rdata.exchange))
        except:
            pass

        # NS records
        try:
            for rdata in dns.resolver.resolve(domain, 'NS'):
                dns_data["NS"].append(str(rdata.target))
        except:
            pass

    except Exception as e:
        pass

    return dns_data


# ======================
# WILDCARD DETECTION
# ======================

def detect_wildcard(domain):
    random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    test_domain = f"{random_sub}.{domain}"
    try:
        answers = dns.resolver.resolve(test_domain, "A")
        ips = [str(rdata) for rdata in answers]
        print(f"[!] Wildcard DNS detected → {ips}")
        return ips
    except:
        print("[+] No wildcard DNS detected.")
        return []


# ======================
# SUBDOMAIN BRUTE FORCE
# ======================

def subdomain_bruteforce(domain, wildcard_ips, wordlist_path="wordlists/subdomains.txt"):
    print(f"\n[+] Starting subdomain brute force for {domain}...\n")
    found_subdomains = []

    try:
        with open(wordlist_path, "r") as file:
            subdomains = file.read().splitlines()

        for sub in subdomains:
            full_sub = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(full_sub, "A")
                ips = [str(rdata) for rdata in answers]

                # If wildcard present, skip if IP matches wildcard IP
                if wildcard_ips and set(ips) == set(wildcard_ips):
                    continue

                print(f"[FOUND] {full_sub} → {', '.join(ips)}")
                found_subdomains.append((full_sub, ips))
            except:
                pass
    except FileNotFoundError:
        print("[!] Wordlist not found. Please create wordlists/subdomains.txt")
    
    return found_subdomains


# ======================
# SAVE REPORT
# ======================

def save_report(domain, whois_data, dns_data, subdomains_data, port_data):
    # Create reports folder if it doesn't exist
    os.makedirs("reports", exist_ok=True)

    # Timestamp for file name & report header
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/scan_report_{domain}_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        # Header
        f.write("========================================\n")
        f.write(" Recon Scanner Report\n")
        f.write(f" Target: {domain}\n")
        f.write(f" Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("========================================\n\n")

        # WHOIS Information
        f.write("[1] WHOIS Information\n")
        f.write("---------------------\n")

        if isinstance(whois_data, dict):
            f.write(f"Domain Name: {whois_data.get('domain_name', 'N/A')}\n")
            f.write(f"Registrar: {whois_data.get('registrar', 'N/A')}\n")
            f.write(f"Registrar URL: {whois_data.get('registrar_url', 'N/A')}\n")
            f.write(f"Creation Date: {whois_data.get('creation_date', 'N/A')}\n")
            f.write(f"Expiration Date: {whois_data.get('expiration_date', 'N/A')}\n")
            f.write(f"Updated Date: {whois_data.get('updated_date', 'N/A')}\n")
            f.write("Name Servers:\n")
            for ns in whois_data.get("name_servers", []):
                f.write(f"  - {ns}\n")
            f.write(f"Contact Email: {whois_data.get('emails', 'N/A')}\n")
            f.write(f"Country: {whois_data.get('country', 'N/A')}\n\n")
        else:
            f.write(str(whois_data) + "\n\n")  # Just print raw string if not dict

        # DNS Records
        f.write("[2] DNS Records\n")
        f.write("---------------\n")
        for record in dns_data.get("A", []):
            f.write(f"A Record: {record}\n")
        for mx in dns_data.get("MX", []):
            f.write(f"MX Record: {mx}\n")
        for ns in dns_data.get("NS", []):
            f.write(f"NS Record: {ns}\n")
        f.write("\n")

        # Subdomains
        f.write("[3] Subdomain Enumeration\n")
        f.write("-------------------------\n")
        if subdomains_data:
            for sub, ip in subdomains_data.items():
                f.write(f"{sub} -> {ip}\n")
        else:
            f.write("No subdomains found from current wordlist.\n")
        f.write("\n")

        # Open Ports
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

        # Footer
        f.write("========================================\n")
        f.write("End of Report\n")
        f.write("Generated by: Recon Scanner v1.0\n")

    print(f"\n[+] Report saved as: {filename}")


# ======================
# MAIN PROGRAM
# ======================

if __name__ == "__main__":
    target = input("Enter target IP or domain: ")

    whois_data = whois_lookup(target)
    dns_data = dns_lookup(target)

    wildcard_ips = detect_wildcard(target)
    subdomains_data = subdomain_bruteforce(target, wildcard_ips)

    port_scan_results = {}
    # Scan main domain
    try:
        main_ip = socket.gethostbyname(target)
        port_scan_results[target] = basic_port_scan(main_ip)
    except:
        pass

    # Scan each subdomain separately
    for sub, ips in subdomains_data:
        for ip in ips:
            port_scan_results[sub] = basic_port_scan(ip)

    save_report(target, whois_data, dns_data, subdomains_data, port_scan_results)
