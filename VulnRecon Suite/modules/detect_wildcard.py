import random
import string
import dns.resolver

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