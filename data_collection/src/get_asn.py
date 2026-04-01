import requests
import ipaddress

def get_asn_prefixes(asn):
    r = requests.get(f"https://ip.guide/as{asn}")
    data = r.json()

    v4 = data["routes"].get("v4", [])
    v6 = data["routes"].get("v6", [])

    networks = [ipaddress.ip_network(prefix) for prefix in v4 + v6]
    return networks

def ips_in_asn(ip_list, asn_num):
    """
    ip_list: list of IP strings
    asn_num: asn number (e.g. 14593)
    """
    networks = get_asn_prefixes(asn_num)
    matching_ips = []

    for ip in ip_list:
        ip_obj = ipaddress.ip_address(ip)
        if any(ip_obj in net for net in networks):
            matching_ips.append(ip)

    return matching_ips
