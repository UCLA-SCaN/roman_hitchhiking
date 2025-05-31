import ast
import ipaddress
import pandas as pd

from .config import PATH

# import starlink geoip data
starlink_geoip_df = pd.read_csv(
    # "https://geoip.starlinkisp.net/",
    f"{PATH}/data/geoip.starlinkisp.net.txt",
    names=['subnet', 'country', 'region', 'city'],
    usecols=list(range(4)),
    index_col=None,
)

def summarize_starlink_geoip(geoip_df: pd.DataFrame = starlink_geoip_df):
   # only inspect ipv4
   geoip_df = geoip_df[~geoip_df['subnet'].apply(lambda x: ':' in x)]

   countries = geoip_df['country'].nunique()
   regions = geoip_df['region'].nunique()
   cities = geoip_df['city'].nunique()
   print('----- Starlink GeoIP Summary -----')
   print(f'number of countries: {countries}')
   print(f'number of regions: {regions}')
   print(f'number of cities: {cities}')
   print('----------------------------------')

   return countries, regions, cities

def get_subnet(ip_str, prefix_length):
  # Create an IPv4 network object
  network = ipaddress.IPv4Network(f'{ip_str}/{prefix_length}', strict=False)

  # Get the network address and subnet mask
  subnet = network.network_address

  return str(subnet) + '/' + str(network.prefixlen)

def get_starlink_geoip(ip_str):
  prefix = 24
  while prefix < 32:
    subnet = get_subnet(ip_str, prefix)
    if subnet in starlink_geoip_df['subnet'].values:
      return subnet
    prefix += 1
  return None

def get_all_geoip(df: pd.DataFrame) -> pd.DataFrame:
    df['subnet'] = df['ip'].apply(get_starlink_geoip)
    df = df.merge(starlink_geoip_df, how='left', on='subnet')
    return df

def get_cleaned_censys(filename: str) -> pd.DataFrame:
    censys_df = pd.read_csv(filename, index_col=0)
    censys_df['dns_name'] = (
        censys_df['dns_name']
        .apply(
            lambda x: ast.literal_eval(x) if isinstance(x, str) else []
        )
    )
    censys_df['dns_name'] = censys_df['dns_name'].apply(lambda x: x[0] if x else None)
    censys_df['pep_link'] = censys_df['pep_link'].apply(lambda x: True if 'True' in x else False)

    # Filter out peplink
    censys_df = censys_df[~censys_df['pep_link']]
    # Filter for customer endpoints
    censys_df = censys_df[censys_df['dns_name'].str.contains(
        r'^customer\..+\.pop\.starlinkisp\.net$', 
        na=False
    )]
    censys_df['dns_trunc'] = censys_df['dns_name'].apply(
      lambda x: x.split('.')[1]
    )
    return censys_df
