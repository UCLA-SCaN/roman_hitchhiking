import ipaddress
import itertools
import threading
import queue
import os
import pandas as pd
import uuid
import subprocess
import sys
import tempfile
import time
from parse_scamper import aggregate_data, paris_tr_to_df
from collections import defaultdict
from enum import Enum
from config import SRC_IPS

class Grouping(Enum):
    SUBNET = 1
    SECLAST = 2

# depending on the pps required you may need to download and build from 
# the source: https://www.caida.org/catalog/software/scamper/
scamper = "scamper" 
pps = 50000

# FIXME
src_ips = ['<INSERT SOURCE IPS HERE>'] 
           
def run_paris_trs(ip_file: str, output_file: str) -> pd.DataFrame:
    """
    Run an ICMP paris-traceroute to every IP address in a given file.

    :param ip_file: file path string to a new-line delimited list of IPs to run traceroutes to
    :param output_file: file path string to .json file to output traceroute data
    """

    cmd_str = f"{scamper} -O json -o {output_file} -p 200 -c \"trace -P icmp-paris -q 1 -g 15 \" {ip_file}"
    print(cmd_str)
    try:
        subprocess.run(
                cmd_str, 
                shell=True, 
        )
    except ValueError:
        raise Exception(f"Invalid command: {cmd_str}")

    return paris_tr_to_df(output_file)

def read_grouped_hops_file(input_file: str) -> pd.DataFrame:
    return pd.read_json(input_file, orient='records', lines=True)

def find_successful_ips(
        dfs: list[pd.DataFrame],
):
    successful_dfs = []
    for df in dfs:
        successful_df = df.dropna(subset=['rtt'])
        successful_df = successful_df[['dst', 'ip_at_ttl', 'probe_ttl']].drop_duplicates()
        successful_dfs.append(successful_df)
    
    df = pd.concat(successful_dfs, ignore_index=True)
    df = df.drop_duplicates(subset=['ip_at_ttl', 'probe_ttl'])
    print(f"BY DF: found number of successful sec_last_ips: {len(df)}")
    return df

def modified_concurrent_ttl_ping_by_grouping(
        df: pd.DataFrame,
        asn: str,
        output_file: str,
        wait_probe: int,
        num_probes: int,
        grouping: Grouping,
        sample_size: int,
        slash: int,
        multiple_src_ips: bool,
        output_dir: str,
        src_ip: str = SRC_IPS[0],
):
    def aggregation_worker():
        nonlocal endpoint_header_written, seclast_header_written

        while not stop_event.is_set() or not aggregation_queue.empty():
            time.sleep(10)

            batch = []
            while not aggregation_queue.empty():
                try:
                    batch.append(aggregation_queue.get_nowait())
                except queue.Empty:
                    break

            if not batch:
                continue

            endpoint_batch = [p for p in batch if p['type'] == 'endpoint']
            seclast_batch = [p for p in batch if p['type'] == 'seclast']

            if endpoint_batch:
                df_batch = aggregate_data(endpoint_batch)
                df_batch.to_csv(
                    endpoint_output_file,
                    mode='a',
                    header=not endpoint_header_written,
                    index=False
                )
                endpoint_header_written = True

            if seclast_batch:
                df_batch = aggregate_data(seclast_batch)
                df_batch.to_csv(
                    sec_last_output_file,
                    mode='a',
                    header=not seclast_header_written,
                    index=False
                )
                seclast_header_written = True

            # cleanup JSON immediately
            for p in batch:
                try:
                    os.remove(p['output_file'])
                except FileNotFoundError:
                    pass

    flush_interval = 10  # seconds

    if grouping == Grouping.SUBNET and (sample_size is None or slash is None):
        raise ValueError("SUBNET grouping must be provided a 'sample_size' and 'slash'")

    if grouping == Grouping.SECLAST and sample_size is None:
        raise ValueError("SECLAST grouping must be provided a 'sample_size'")

    tmp_output_dir = os.path.join(output_dir, f"tmp_output_{asn}")
    os.makedirs(tmp_output_dir, exist_ok=True)

    endpoint_ip_input_file = {}
    presat_ip_input_file = {}

    ###########################################################################
    # Sampling
    ###########################################################################
    if grouping == Grouping.SUBNET:
        df['subnet'] = df['dst'].apply(
            lambda x: ipaddress.IPv4Network(x + f"/{slash}", strict=False)
        )
        df_sampled = df.groupby('subnet', group_keys=False).head(sample_size)
    elif grouping == Grouping.SECLAST:
        df_sampled = df.groupby('sec_last_ip', group_keys=False).head(sample_size)
    else:
        df_sampled = df

    ###########################################################################
    # Endpoint grouping
    ###########################################################################
    endpoints_grouped = (
        df_sampled
        .groupby('hop_count')['dst']
        .apply(set)
        .reset_index()
    )

    for _, row in endpoints_grouped.iterrows():
        ips = row['dst']
        hop = int(row['hop_count'])
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            endpoint_ip_input_file[hop] = tmp.name
            for ip in ips:
                tmp.write(ip + '\n')

    ###########################################################################
    # Presat grouping
    ###########################################################################
    presat_endpoints = (
        df_sampled
        .groupby(['sec_last_ip', 'sec_last_hop'])['dst']
        .first()
        .reset_index()
    )

    presat_endpoints = presat_endpoints.merge(
        df_sampled[['dst', 'sec_last_ip', 'sec_last_hop', 'hop_count']],
        how='left',
        on=['dst', 'sec_last_ip', 'sec_last_hop']
    )

    presat_endpoint_grouped = (
        presat_endpoints
        .groupby(['sec_last_hop', 'hop_count'])['dst']
        .apply(set)
        .reset_index()
    )

    for _, row in presat_endpoint_grouped.iterrows():
        ips = row['dst']
        hop = int(row['sec_last_hop'])
        endpoint_hop = int(row['hop_count'])
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            presat_ip_input_file[(hop, endpoint_hop)] = tmp.name
            for ip in ips:
                tmp.write(ip + '\n')

    ###########################################################################
    # Streaming Ping Loop
    ###########################################################################

    running_procs = []

    aggregation_queue = queue.Queue()
    stop_event = threading.Event()

    endpoint_output_file = f"{output_file}_endpoint.csv"
    sec_last_output_file = f"{output_file}_sec_last.csv"

    endpoint_header_written = os.path.exists(endpoint_output_file)
    seclast_header_written = os.path.exists(sec_last_output_file)

    if num_probes == 0:
        seq_iter = itertools.count()
    else:
        seq_iter = range(num_probes)

    worker_thread = threading.Thread(target=aggregation_worker, daemon=True)
    worker_thread.start()

    for seq in seq_iter:
        start_time = time.time()

        # Spawn endpoint probes
        for hop, file in endpoint_ip_input_file.items():
            if multiple_src_ips:
                src_ip = SRC_IPS[hop % len(SRC_IPS)]

            temp_out = f"{tmp_output_dir}/endpoint_{seq}_{uuid.uuid4().hex}.json"

            cmd = [
                scamper, "-O", "json", "-o", temp_out, "-p", str(pps),
                "-c", f"trace -P icmp-paris -S {src_ip} -q 1 -f {hop} -m {hop}",
                file
            ]

            proc = subprocess.Popen(cmd)

            running_procs.append({
                'proc': proc,
                'type': 'endpoint',
                'seq': seq,
                'hop': hop,
                'input_file': file,        # ← restore this
                'output_file': temp_out,
            })

        # Spawn presat probes
        for (hop, endpoint_hop), file in presat_ip_input_file.items():
            if multiple_src_ips:
                src_ip = SRC_IPS[endpoint_hop % len(SRC_IPS)]

            temp_out = f"{tmp_output_dir}/seclast_{seq}_{uuid.uuid4().hex}.json"

            cmd = [
                scamper, "-O", "json", "-o", temp_out, "-p", str(pps),
                "-c", f"trace -P icmp-paris -S {src_ip} -q 1 -f {hop} -m {hop}",
                file
            ]

            proc = subprocess.Popen(cmd)

            running_procs.append({
                'proc': proc,
                'type': 'seclast',
                'seq': seq,
                'hop': hop,
                'input_file': file,        # ← restore this
                'output_file': temp_out,
            })

        # Maintain probe rate
        to_sleep = wait_probe - (time.time() - start_time)
        if to_sleep > 0:
            time.sleep(to_sleep)


        completed = [p for p in running_procs if p['proc'].poll() is not None]

        for p in completed:
            aggregation_queue.put(p)
            running_procs.remove(p)

    ###########################################################################
    # Final flush (for finite mode)
    ###########################################################################
    for p in running_procs:
        p['proc'].wait()
        aggregation_queue.put(p)

    stop_event.set()
    worker_thread.join()

    ###########################################################################
    # Cleanup input temp files
    ###########################################################################
    for file in endpoint_ip_input_file.values():
        os.remove(file)

    for file in presat_ip_input_file.values():
        os.remove(file)

    print("Finished streaming aggregation.")

def concurrent_ttl_ping_by_grouping(
        df: pd.DataFrame, asn: str, output_file: str, 
        wait_probe: int = 1, num_probes: int = 60,
        grouping: Grouping = None, sample_size: int = None,
        slash: int = None, multiple_src_ips: bool = False,
        src_ip: str = SRC_IPS[0],
):
    if grouping == Grouping.SUBNET and (sample_size is None or slash is None):
        raise ValueError("SUBNET grouping must be provided a 'sample_size' and 'slash'")

    if grouping == Grouping.SECLAST and sample_size is None:
        raise ValueError("SECLAS grouping must be provided a 'sample_size'")

    output_dir = f"tmp_modified_concurrent_output_{asn}"
    os.makedirs(output_dir, exist_ok=True)

    ###########################################################################
    # Only ping `sample_size` IPs from each group
    ###########################################################################
    if grouping == Grouping.SUBNET:
        df['subnet'] = (
            df['dst']
            .apply(
                lambda x: ipaddress.IPv4Network(x + f"/{slash}", strict=False)
            )
        )
        df_sampled = df.groupby('subnet', group_keys=False).head(sample_size)
    elif grouping == Grouping.SECLAST:
        df_sampled = df.groupby('sec_last_ip', group_keys=False).head(sample_size)
    else:
        df_sampled = df

    ###########################################################################
    # Find endpoints to ping
    ###########################################################################
    endpoints_grouped = (
        df_sampled
        .groupby('hop_count')['dst']
        .apply(set)
        .reset_index()
    )

    endpoint_ip_input_file = {}
    for index, row in endpoints_grouped.iterrows():
        ips = row['dst']
        hop = int(row['hop_count'])
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_ip_file:
            endpoint_ip_input_file[hop] = tmp_ip_file.name
            tmp_ip_file.flush()
            for idx, ip in enumerate(ips):
                tmp_ip_file.write(ip + '\n')
            tmp_ip_file.seek(0)

    ###########################################################################
    # Find presat to ping
    ###########################################################################
    presat_grouped = (
        df_sampled
        .groupby(['sec_last_hop', 'hop_count'])['dst']
        .apply(list)
        .reset_index()
    )

    presat_ip_input_file = {}
    for index, row in presat_grouped.iterrows():
        ips = row['dst']
        hop = int(row['sec_last_hop'])
        endpoint_hop = int(row['hop_count'])
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_ip_file:
            presat_ip_input_file[(hop, endpoint_hop)] = tmp_ip_file.name
            tmp_ip_file.flush()
            for idx, ip in enumerate(ips):
                tmp_ip_file.write(ip + '\n')
            tmp_ip_file.seek(0)
    
    ###########################################################################
    # Ping
    ###########################################################################
    endpoint_output_files = []
    presat_output_files = []
    procs = []

    for seq in range(num_probes):
        start_time = time.time()
        for hop, file in endpoint_ip_input_file.items():
            # ping endpoints
            if multiple_src_ips:
                src_ip = SRC_IPS[hop % len(SRC_IPS)]
            temp_endpoint_out = f"{output_dir}/endpoint_{seq}_{uuid.uuid4().hex}.json"
            cmd_list = [
                scamper, "-O", "json", "-o", temp_endpoint_out, "-p", str(pps), 
                "-c", f"trace -P icmp-paris -S {src_ip} -q 1 -f {hop} -m {hop}", file
            ]
            proc = subprocess.Popen(cmd_list)
            procs.append(proc)
            endpoint_output_files.append({
                'seq': seq,
                'hop': hop, 
                'input_file': file,
                'output_file': temp_endpoint_out,
            })

        for (hop, endpoint_hop), file in presat_ip_input_file.items():
            # ping presats
            if multiple_src_ips:
                src_ip = SRC_IPS[endpoint_hop % len(SRC_IPS)]
            temp_sec_last_out = f"{output_dir}/seclast_{seq}_{uuid.uuid4().hex}.json"
            cmd_list = [
                scamper, "-O", "json", "-o", temp_sec_last_out, "-p", str(pps), 
                "-c", f"trace -P icmp-paris -S {src_ip} -q 1 -f {hop} -m {hop}", file
            ]
            proc = subprocess.Popen(cmd_list)
            procs.append(proc)
            presat_output_files.append({
                'seq': seq,
                'hop': hop, 
                'input_file': file,
                'output_file': temp_sec_last_out,
            })

        to_sleep = wait_probe - (time.time() - start_time)
        if to_sleep > 0:
            time.sleep(to_sleep)

    # Wait for all subprocesses to complete
    for proc in procs:
        proc.wait()

    endpoint_df = aggregate_data(endpoint_output_files)
    presat_df = aggregate_data(presat_output_files)

    endpoint_output_file = f"{output_file}_endpoint.csv"
    endpoint_df.to_csv(endpoint_output_file)

    sec_last_output_file = f"{output_file}_sec_last.csv"
    presat_df.to_csv(sec_last_output_file)

    ###########################################################################
    # Clean up files
    ###########################################################################
    for file in endpoint_ip_input_file.values():
        os.remove(file)

    for file in presat_ip_input_file.values():
        os.remove(file)

    for file_info in endpoint_output_files:
        os.remove(file_info['output_file'])

    for file_info in presat_output_files:
        os.remove(file_info['output_file'])

    ###########################################################################
    # Print success rate
    ###########################################################################
    print(f"-----------------------------------------------------------------")
    if grouping is not None:
        print(f"{'/' + str(slash) + " with " if slash else ""} {sample_size} samples stats")
    num_endpoint = endpoint_df['dst'].nunique()
    num_seclast = presat_df['ip_at_ttl'].nunique()
    print(f"num endpoints: {num_endpoint}")
    print(f"num seclast: {num_seclast}")
    df = (
        endpoint_df
        .merge(
            presat_df[['seq', 'dst', 'ip_at_ttl', 'rtt']], 
            how='left', 
            on=['seq', 'dst'],
            suffixes=['_endpoint', '_seclast'],
        )
    )
    successful_df = df.dropna(subset=['rtt_endpoint', 'rtt_seclast'])
    successful_counts = (
        successful_df
        .groupby('dst')['seq']
        .nunique()
        .reset_index(name='unique_seq_count')
    )
    successful_counts_desc = successful_counts['unique_seq_count'].describe()
    print(successful_counts_desc)
    print(f"-----------------------------------------------------------------")

    return successful_counts_desc

def concurrent_ttl_ping(
        df: pd.DataFrame, 
        asn: str, 
        output_file: str, 
        wait_probe: int = 1, 
        num_probes: int = 60,
        src_ip: str = SRC_IPS[0],
):
    endpoint_output_file = f"{output_file}_endpoint.csv"
    sec_last_output_file = f"{output_file}_sec_last.csv"

    pps = 50000

    endpoint_ip_input_file = {}
    presat_ip_input_file = {}
    endpoint_temp_files = []
    presat_temp_files = []
    procs = []

    output_dir = f"tmp_modified_concurrent_output_{asn}"
    os.makedirs(output_dir, exist_ok=True)

    endpoints_grouped = df.groupby('hop_count')['dst'].apply(list).reset_index()
    for index, row in endpoints_grouped.iterrows():
        ips = row['dst']
        hop = int(row['hop_count'])
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_ip_file:
            endpoint_ip_input_file[hop] = tmp_ip_file.name
            tmp_ip_file.flush()
            for idx, ip in enumerate(ips):
                tmp_ip_file.write(ip + '\n')
            tmp_ip_file.seek(0)

    # find presat to ping
    presat_grouped = df.groupby('sec_last_hop')['dst'].apply(list).reset_index()
    for index, row in presat_grouped.iterrows():
        ips = row['dst']
        hop = int(row['sec_last_hop'])
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_ip_file:
            presat_ip_input_file[hop] = tmp_ip_file.name
            tmp_ip_file.flush()
            for idx, ip in enumerate(ips):
                tmp_ip_file.write(ip + '\n')
            tmp_ip_file.seek(0)

    for seq in range(num_probes):
        start_time = time.time()
        for hop, file in endpoint_ip_input_file.items():
            # ping endpoints
            temp_endpoint_out = f"{output_dir}/endpoint_{seq}_{uuid.uuid4().hex}.json"
            cmd_list = [
                scamper, "-O", "json", "-o", temp_endpoint_out, "-p", str(pps), 
                "-c", f"trace -P icmp-paris -S {src_ip} -q 1 -f {hop} -m {hop}", file
            ]
            proc = subprocess.Popen(cmd_list)
            procs.append(proc)
            endpoint_temp_files.append(temp_endpoint_out)

        for hop, file in presat_ip_input_file.items():
            # ping presats
            temp_sec_last_out = f"{output_dir}/endpoint_{seq}_{uuid.uuid4().hex}.json"
            cmd_list = [
                scamper, "-O", "json", "-o", temp_sec_last_out, "-p", str(pps), 
                "-c", f"trace -P icmp-paris -S {src_ip} -q 1 -f {hop} -m {hop}", file
            ]
            proc = subprocess.Popen(cmd_list)
            procs.append(proc)
            presat_temp_files.append(temp_sec_last_out)

        to_sleep = wait_probe - (time.time() - start_time)
        if to_sleep > 0:
            time.sleep(to_sleep)

    # Wait for all subprocesses to complete
    for proc in procs:
        proc.wait()

    endpoint_df = aggregate_data(endpoint_temp_files)
    presat_df = aggregate_data(presat_temp_files)

    endpoint_df.to_csv(endpoint_output_file)
    presat_df.to_csv(sec_last_output_file)

    # Clean up files
    for file in endpoint_ip_input_file.values():
        os.remove(file)

    for file in presat_ip_input_file.values():
        os.remove(file)

    for file in endpoint_temp_files:
        os.remove(file)

    for file in presat_temp_files:
        os.remove(file)

    return

def round_robin_ttl_ping(
        df: pd.DataFrame, 
        output_file: str, 
        wait_probe: int = 1, 
        num_probes: int = 60, 
        sec_last_only: bool =False,
        src_ip: str = SRC_IPS[0],
):
    endpoint_output_file = f"{output_file}_endpoint.csv"
    sec_last_output_file = f"{output_file}_sec_last.csv"

    df = (
        df
        .groupby(['sec_last_ip', 'sec_last_hop', 'hop_count'])['dst']
        .apply(set)
        .reset_index()
    )
    ip_input_files = {} 
    endpoint_temp_files = []
    sec_last_temp_files = []

    output_dir = "tmp_output"
    os.makedirs(output_dir, exist_ok=True)

    itr_dict = defaultdict(list)

    # want IPs with the same sec_last_hop in one file, but not the same sec_last_ip
    # df has grouped with same sec_last_hop and same sec_last_ip
    sec_last_hops = list(df['sec_last_hop'].unique())
    endpoint_hops = list(df['hop_count'].unique())
    for sec_last_hop in sec_last_hops:
        for endpoint_hop in endpoint_hops:
            temp_df = df[df['sec_last_hop'] == sec_last_hop]
            temp_df = temp_df[temp_df['hop_count'] == endpoint_hop]
            for ind, row in temp_df.iterrows():
                ip_list = list(row['dst'])
                sec_last_ip = row['sec_last_ip']
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_ip_file:
                    tmp_ip_file.flush()
                    ip_list = list(row['dst'])
                    for ip in ip_list:
                        tmp_ip_file.write(ip + '\n')
                    tmp_ip_file.seek(0)
                    ip_input_files[(endpoint_hop, sec_last_hop, sec_last_ip)] = tmp_ip_file.name
                    itr_dict[sec_last_hop].append({
                        "endpoint_hop": int(endpoint_hop),
                        "sec_last_hop": int(sec_last_hop),
                        "file_name": tmp_ip_file.name,
                    })
    
    # ping for 'num_probes' 
    for seq in range(num_probes):
        print(f"pinging seq: ({seq}/{num_probes}) \t {(seq/num_probes):.2%}")
        start_time = time.time()
        max_entry_list_len = max(len(v) for v in itr_dict.values())
        # take the ith entry from each sec_last_ip
        for i in range(max_entry_list_len):
            processes = []
            for file_list in itr_dict.values():
                if i >= len(file_list):
                    continue
                to_ping_info = file_list[i]
                try:
                    process = {}
                    # start endpoint processes
                    if not sec_last_only:
                        temp_endpoint_out = f"{output_dir}/endpoint_{seq}_{uuid.uuid4().hex}.json"
                        cmd_list = [
                            scamper, "-O", "json", "-o", temp_endpoint_out, "-p", str(pps), 
                            "-c", f"trace -P icmp-paris -S {src_ip} -q 1 -f {to_ping_info["endpoint_hop"]} -m {to_ping_info["endpoint_hop"]}", 
                            to_ping_info["file_name"],
                        ]
                        endpoint_p = subprocess.Popen(cmd_list)
                        process["endpoint_process"] = endpoint_p
                        endpoint_temp_files.append(temp_endpoint_out)

                    # start second-to-last processes
                    temp_sec_last_out = f"{output_dir}/presat_{seq}_{uuid.uuid4().hex}.json"
                    cmd_list = [
                        scamper, "-O", "json", "-o", temp_sec_last_out, "-p", str(pps), 
                        "-c", f"trace -P icmp-paris -S {src_ip} -q 1 -f {to_ping_info["sec_last_hop"]} -m {to_ping_info["sec_last_hop"]}", 
                        to_ping_info["file_name"],
                    ]
                    sec_last_p = subprocess.Popen(cmd_list)
                    process["sec_last_process"] = sec_last_p
                    sec_last_temp_files.append(temp_sec_last_out)

                    processes.append(process)
                except ValueError as e:
                    print("failed to run ttl for ip: {ip} with ttl: {ttl}\n Error: {e}", 
                            file=sys.stderr)

            # Wait for all to finish, collect output
            for proc_info in processes:
                if not sec_last_only:
                    endpoint_p = proc_info["endpoint_process"]
                    endpoint_p.wait()

                sec_last_p = proc_info["sec_last_process"]
                sec_last_p.wait()

        time_to_process = time.time()
        to_sleep = wait_probe - (time_to_process - start_time)
        if to_sleep > 0:
            time.sleep(to_sleep)

    endpoint_df = aggregate_data(endpoint_temp_files)
    sec_last_df = aggregate_data(sec_last_temp_files)

    endpoint_df.to_csv(endpoint_output_file)
    sec_last_df.to_csv(sec_last_output_file)

    # Clean up temporary files
    for file in ip_input_files.values():
        os.remove(file)

    for file in endpoint_temp_files:
        os.remove(file)

    for file in sec_last_temp_files:
        os.remove(file)
