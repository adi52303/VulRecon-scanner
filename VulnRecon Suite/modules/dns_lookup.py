import dns.resolver

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

