import whois

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

