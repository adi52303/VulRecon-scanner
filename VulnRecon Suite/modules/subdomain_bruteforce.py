import os
import requests
import dns.resolver

def subdomain_bruteforce(domain, wildcard_ips):
    # Dynamically get the path to the wordlist in the VulnRecon Suite root
    project_root = os.path.dirname(os.path.abspath(__file__))  # this points to modules/
    project_root = os.path.dirname(project_root)  # go one level up to project root
    wordlist_path = os.path.join(project_root, "wordlists", "subdomains.txt")

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
        print(f"[!] Wordlist not found at {wordlist_path}")

    return found_subdomains
