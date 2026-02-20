import pandas as pd
import requests
from .constants import IPINFO_TOKEN

def get_asn(ip: str, token: str=IPINFO_TOKEN) -> str:
    req_str = f"https://api.ipinfo.io/lite/{ip}?token={token}"
    response = requests.get(req_str)
    data = response.json()
    try: 
        return data['asn']
    except KeyError as e:  # Catch the specific exception if the key is missing
        print(f"KeyError: The key 'asn' was not found for ip {ip}. Error: {e}: {data}")
    except ValueError as e:  # You can still catch ValueError if needed, just for other cases
        print(f"ValueError: {e}: {data}")

def get_all_asn(presat_ips: list) -> pd.DataFrame:
    print(presat_ips)
    asn_col = []

    for ip in presat_ips:
        asn = get_asn(ip)
        asn_col.append(asn)

    df = pd.DataFrame({
        'ip': presat_ips,
        'asn': asn_col,
    })
    
    return df
