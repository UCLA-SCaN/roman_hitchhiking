import json
import ipaddress
import os
import pandas as pd
from datetime import datetime, timezone
from typing import Optional

from src.get_asn import ips_in_asn


def read_jsonl_records(file_path: str, skip_corrupt: bool = True, max_reports: int = 10) -> list[dict]:
    """Read JSON Lines while skipping corrupted records."""
    records = []
    bad_lines = 0
    with open(file_path, 'rb') as f:
        for lineno, raw_line in enumerate(f, 1):
            line = raw_line.strip(b'\x00').strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                bad_lines += 1
                if skip_corrupt:
                    if bad_lines <= max_reports:
                        print(f"Skipping corrupted JSON line {lineno} in {file_path}: {e}")
                        print(line)
                    continue
                raise
    if bad_lines and skip_corrupt:
        print(f"Skipped {bad_lines} corrupted JSON lines in {file_path}")
    return records


def get_last_hops_from_paris_tr(
        file_path: str, asn_num: Optional[str] = None, sat_hop: int = -2,
) -> pd.DataFrame:
    """
    Extract the hop number and IPs for the second-to-last and last hop in
    ICMP paris-traceroutes.

    :param file_path: file path to the .json formatted scamper trace output
    :param asn_num: AS number (optional)
    :return: dataframe with the IPs and hop numbers of the second-to-last and
    last hops in the traceroutes as well as the stop reason.
    """

    def sort_hops(e):
        return e['probe_ttl']

    def get_sec_last_ip(hops, sat_hop: int = -2):
        # If the list has fewer than two elements, return None
        if not isinstance(hops, list) or len(hops) < abs(sat_hop):
            return None
        hops.sort(key=sort_hops)
        return hops[int(sat_hop)]['addr']

    def get_sec_last_probe_ttl(hops, sat_hop: int = -2):
        # If the list has fewer than two elements, return None
        if not isinstance(hops, list) or len(hops) < abs(sat_hop):
            return None
        hops.sort(key=sort_hops)
        return hops[int(sat_hop)]['probe_ttl']

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Scamper output file not found: {file_path}")
    
    if os.path.getsize(file_path) == 0:
        raise ValueError(f"Scamper output file is empty: {file_path}. "
                        f"This usually means scamper failed to execute. "
                        f"Common causes: 1) Missing permissions (needs root/CAP_NET_RAW), "
                        f"2) Invalid IPs in input file, 3) Scamper not installed.")

    records = read_jsonl_records(file_path, skip_corrupt=True)
    if not records:
        raise ValueError(f"No valid JSON records found in {file_path}")

    df = pd.DataFrame.from_records(records)
    print('printing get_last_hops_from_paris_tr')
    print(df)
    print(df.columns)

    # filter for only 'trace' data
    df = df[df["type"] == "trace"]
    df['sec_last_ip'] = df['hops'].apply(lambda x: get_sec_last_ip(x, sat_hop=sat_hop))
    df['sec_last_hop'] = df['hops'].apply(lambda x: get_sec_last_probe_ttl(x, sat_hop=sat_hop))
    df = df[['dst', 'stop_reason', 'hop_count', 'sec_last_ip', 'sec_last_hop']]

    # ensure all second-to-last-hops are from correct ASN (eliminate traceroutes with little visibility)
    sec_last_ips = df['sec_last_ip'].dropna().unique().tolist()

    is_v6 = ipaddress.ip_address(df['dst'].iloc[0]).version == 6

    if asn_num is None or asn_num == "CONTROL" or is_v6:
        return df
    
    validated_sec_last_ips = ips_in_asn(sec_last_ips, asn_num)
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
    # Check if file exists and is not empty
    import os
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Scamper output file not found: {file_path}")
    
    if os.path.getsize(file_path) == 0:
        raise ValueError(f"Scamper output file is empty: {file_path}. "
                        f"This usually means scamper failed to execute or produced no output.")
    
    records = read_jsonl_records(file_path, skip_corrupt=True)
    if not records:
        raise ValueError(f"No valid JSON records found in {file_path}")

    df = pd.DataFrame.from_records(records)
    df = df[df['type'] == 'trace']
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

    dfs = [df for df in dfs if df is not None and not df.empty]
    all_dfs = pd.concat(dfs, ignore_index=True)
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
