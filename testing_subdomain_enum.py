import requests

def dedup_www(subdomains):
    cleaned = set(subdomains)
    for sub in subdomains:
        stripped = sub
        if sub.startswith("www."):
            stripped = sub[4:]
        elif sub.startswith("*."):
            stripped = sub[2:]

        if stripped in cleaned and sub != stripped:
            cleaned.discard(sub)

    return sorted(cleaned)


def get_crtsh_subdomains(domain):
    crtsh_count = 0
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value")
            if name:
                for sub in name.splitlines():
                    if sub.endswith(domain):
                        subdomains.add(sub.lower())
        subdomains = dedup_www(subdomains)
        crtsh_count += len(subdomains)
        print(f"crtsh_subdomains: {crtsh_count}")
        return sorted(subdomains)
    except Exception as e:
        print(f"[crt.sh] Error: {e}")
        return []

        
crtsh_subdomains = get_crtsh_subdomains("tesla.com")
for s in crtsh_subdomains:
    print(s)

# def get_otx_subdomains(domain):
#     otx_count = 0
#     url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
#     try:
#         response = requests.get(url)
#         response.raise_for_status()
#         data = response.json()
#         subdomains = set()
#         for record in data.get("passive_dns", []):
#             hostname = record.get("hostname")
#             if hostname and hostname.endswith(domain):
#                 subdomains.add(hostname.lower())
#         subdomains = dedup_www(subdomains)
#         otx_count += len(subdomains)
#         print(f"otx_subdomains: {otx_count}")
#         return sorted(subdomains)
#     except Exception as e:
#         print(f"[OTX] Error: {e}")
#         return []

# def get_wayback_subdomains(domain):
#     way_back_count = 0
#     url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original"
#     try:
#         response = requests.get(url)
#         response.raise_for_status()
#         entries = response.json()[1:]  # Skip header
#         subdomains = set()
#         for row in entries:
#             full_url = row[0]
#             host = full_url.split('/')[2] if '://' in full_url else full_url.split('/')[0]
#             if host.endswith(domain):
#                 subdomains.add(host.lower())
#         subdomains = dedup_www(subdomains)
#         way_back_count += len(subdomains)
#         print(f"way_back_subdomains: {way_back_count}")
#         return sorted(subdomains)   
#     except Exception as e:
#         print(f"[Wayback] Error: {e}")
#         return []


# print("\n\n")
# otx_subdomains = get_otx_subdomains("apisec.ai")
# for s in otx_subdomains:
#     print(s)

# print("\n\n")
# way_back_subdomains = get_wayback_subdomains("apisec.ai")
# for s in way_back_subdomains:
#     print(s)

