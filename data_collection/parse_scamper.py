import json
import pandas as pd
from datetime import datetime, timezone

from src.get_asn import get_all_asn

def get_last_hops_from_paris_tr(file_path: str, asn: str) -> pd.DataFrame:
    """
    Extract the hop number and IPs for the second-to-last and last hop in
    ICMP paris-traceroutes.

    :param file_path: file path to the .json formatted scamper trace output
    :return: dataframe with the IPs and hop numbers of the second-to-last and
    last hops in the traceroutes as well as the stop reason.
    """

    def sort_hops(e):
        return e['probe_ttl']

    def get_sec_last_ip(hops):
        # If the list has fewer than two elements, return None
        if not isinstance(hops, list) or len(hops) < 2:
            return None
        hops.sort(key=sort_hops)
        return hops[-2]['addr']

    def get_sec_last_probe_ttl(hops):
        # If the list has fewer than two elements, return None
        if not isinstance(hops, list) or len(hops) < 2:
            return None
        hops.sort(key=sort_hops)
        return hops[-2]['probe_ttl']

    df = pd.read_json(file_path, lines=True)
    print('printing get_last_hops_from_paris_tr')
    print(df)
    print(df.columns)

    # filter for only 'trace' data
    df = df[df["type"] == "trace"]
    df['sec_last_ip'] = df['hops'].apply(lambda x: get_sec_last_ip(x))
    df['sec_last_hop'] = df['hops'].apply(lambda x: get_sec_last_probe_ttl(x))
    df = df[['dst', 'stop_reason', 'hop_count', 'sec_last_ip', 'sec_last_hop']]

    # ensure all second-to-last-hops are from correct ASN (eliminate traceroutes with little visibility)
    sec_last_ips = list(df['sec_last_ip'].unique())
    asn_df = get_all_asn(sec_last_ips)
    print(asn_df)
    asn_df = asn_df[asn_df['asn'] == asn]
    validated_sec_last_ips = asn_df['ip'].tolist()
    
    old_df_len = len(df)
    df = df[df['sec_last_ip'].isin(validated_sec_last_ips)]
    new_df_len = len(df)
    print(f"filtered for valid sec-to-last hops:")
    print(f"\t({old_df_len} - {new_df_len}) {old_df_len - new_df_len} line filtered out")

    return df

def paris_tr_to_df(file_path: str) -> pd.DataFrame:
    """
    Cleans paris traceroute json output file and outputs as a Dataframe.

    :param file_path: file path of the scamper paris-traceroute json output
    """
    df = pd.read_json(file_path, orient='records', lines=True)
    df = df[df['type'] == 'trace']

    df_exploded = df.explode('hops').reset_index(drop=True)
    hops_df = pd.json_normalize(df_exploded['hops'])
    df = pd.concat([df_exploded.drop(columns=['hops']), hops_df], axis=1)

    df = df[[
        'dst', 'stop_reason',
        'stop_data', 'start', 'hop_count',
        'probe_count', 'addr',
        'probe_ttl', 'probe_id', 
        'rtt', 
    ]]

    df = df[df['stop_reason'] == 'COMPLETED']

    return df

def ping_to_df(file_path: str) -> pd.DataFrame:
    data = []
    with open(file_path, "r") as file:
        for line in file:
            entry = json.loads(line)  # Parse JSON line
            if entry.get("type") == "ping":  # Filter only "ping" entries
                dst = entry.get("dst")  # Extract "dst"
                start_time = entry.get("start", {}).get("sec")  # Extract "start" time (only seconds)
                
                for response in entry.get("responses", []):
                    row = {
                        "date": datetime.fromtimestamp(start_time, tz=timezone.utc).strftime('%Y-%m-%d'),
                        "seq": response.get("seq"),
                        "dst": dst,
                        "start_time": response.get("tx", {}).get("sec"),
                        "start_sec": response.get("tx", {}).get("usec"),
                        "rtt": response.get("rtt"),
                    }
                    data.append(row)

    # Convert to DataFrame
    df = pd.DataFrame(data)
    return df

def aggregate_data(files_info: list) -> pd.DataFrame:
    """
    Aggregates data from list of files containing scamper outputs when running ttl_ping
    into a single file.

    :param files: list of .json files from scamper output
    :return: a single aggregated dataframe with column for seq numbers
    """

    def get_date(start):
        try:
            return start['ftime'].split()[0]
        except:
            return None

    def get_start_time(start):
        try:
            return start['ftime']
        except:
            return None

    def get_start_sec(start):
        try:
            return start['sec']
        except:
            return None

    def get_rtt(hops):
        try: 
            return hops[0]['rtt']
        except:
            return None
    def get_probe_ttl(hops):
        try:
            return hops[0]['probe_ttl']
        except:
            return None
    def get_ip_at_ttl(hops):
        try:
            return hops[0]['addr']
        except:
            return None

    dfs = []
    for idx, f_info in enumerate(files_info):
        seq = f_info['seq']
        input_file_name = f_info['input_file']
        hop = f_info['hop']
        df = pd.DataFrame()
        try:
            df = pd.read_json(f_info['output_file'], lines=True, convert_dates=False)
        except Exception as e:
            print("Could not load json file with seq: " + str(seq))
            print(e)
            continue

        if df.empty:
            print(f"File was empty: {input_file_name}")
            with open(input_file_name, 'r') as f:
                print(f.read())
            print("\n\n\n")
            continue
        try: 
            df = df[df['type'] == 'trace']
            if len(df) == 0:
                continue
            df['date'] = df['start'].apply(get_date)
            df['seq'] = [seq] * len(df)
            df['start_time'] = df['start'].apply(get_start_time)
            df['start_sec'] = df['start'].apply(get_start_sec)
            if 'hops' in df.columns:
                df['ip_at_ttl'] = df['hops'].apply(get_ip_at_ttl)
                df['probe_ttl'] = df['hops'].apply(get_probe_ttl)
                df['rtt'] = df['hops'].apply(get_rtt)
            else:
                df['ip_at_ttl'] = [None] * len(df)
                df['probe_ttl'] = [None] * len(df)
                df['rtt'] = [None] * len(df)
            df = df[[
                'date', 'seq', 'dst', 'stop_reason', 'start_time', 'start_sec', 
                'hop_count', 'ip_at_ttl', 'probe_ttl', 'rtt',
            ]]
        except Exception as e:
            print(f"Could not parse: {e}")
            print(f"Using input_file: {input_file_name} on hop: {hop}")
            with open(input_file_name, 'r') as f:
                print(f.read())
            print("\n\n\n")
        dfs.append(df)

    if len(dfs) == 0:
        return pd.DataFrame(columns=['date',
            'seq',
            'dst',
            'stop_reason',
            'start_time',
            'start_sec',
            'hop_count',
            'ip_at_ttl',
            'probe_ttl',
            'rtt'])

    all_dfs = pd.concat(dfs)
    all_dfs.astype({
        'date': 'str', 
        'seq': 'int32', 
        'dst': 'str', 
        'stop_reason': 'str', 
        'start_time': 'str', 
        'start_sec': 'int32', 
        'hop_count': 'int32', 
        'ip_at_ttl': 'str', 
        'probe_ttl': 'float', 
        'rtt': 'float'
        }).dtypes

    return all_dfs
