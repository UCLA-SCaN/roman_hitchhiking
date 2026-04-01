import threading
import queue
import os
import fcntl
import json
import shutil
import pandas as pd
import uuid
import subprocess
import sys
import tempfile
import time

from contextlib import contextmanager
from parse_scamper import paris_tr_to_df
from enum import Enum
from config import SRC_IPS
from src.helper import get_sl_files, get_time_bucket_file
from src.rhh_processing import process_ttl_ping_bucket

# depending on the pps required you may need to download and build from 
# the source: https://www.caida.org/catalog/software/scamper/
scamper = "scamper" 
pps = 50000

MAX_CONCURRENT = 1000   # tune this
PROC_TIMEOUT = 10      # seconds before killing stuck scamper

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

def get_ep_ips(ep_sl_file: str):
    ep_ip_input_files = {}

    sl_df = pd.read_csv(ep_sl_file)
    eps = sl_df['dst'].unique().tolist()
    print("*" * 80)
    print(f"endpoints: {len(eps)}")

    for i, src_ip in enumerate(SRC_IPS):
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            ep_ip_input_files[src_ip] = tmp.name
            for j, ip in enumerate(eps):
                if j % len(SRC_IPS) == i:
                    tmp.write(ip + '\n')
            print(f"created temp file for endpoints: {tmp.name}")

    return ep_ip_input_files

def get_sl_ips(mapping_file: str):
    sl_ip_input_files = {}

    sl_ep_map_df = pd.read_csv(mapping_file)
    sl_ep_grouped = (
        sl_ep_map_df
        .groupby('sl_hop')['ep_ip']
        .apply(set)
        .reset_index()
    )

    print("*" * 80)
    print(f"second-to-last: {len(sl_ep_map_df)}")

    for _, row in sl_ep_grouped.iterrows():
        ips = row['ep_ip']
        hop = int(row['sl_hop'])
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            sl_ip_input_files[hop] = tmp.name
            for ip in ips:
                tmp.write(ip + '\n')

    return sl_ip_input_files

def cleanup_temp_files(*file_maps):
    """
    Removes temporary files from a file dictionary.
    """

    for file_map in file_maps:
        for filepath in file_map.values():
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception as e:
                print(
                    f"Warning: failed to delete {filepath}: {e}"
                )


def _append_valid_json_lines(source_path: str, dest_path: str) -> dict[str, int]:
    written_lines = 0
    skipped_lines = 0

    with open(source_path, "r", encoding="utf-8", errors="replace") as f_in, \
        open(dest_path, "a", encoding="utf-8") as f_out:
        for line_number, raw_line in enumerate(f_in, 1):
            cleaned_line = raw_line.replace("\x00", "").strip()
            if not cleaned_line:
                skipped_lines += 1
                continue

            try:
                json.loads(cleaned_line)
            except json.JSONDecodeError:
                skipped_lines += 1
                print(
                    "Skipping malformed scamper output line "
                    f"{line_number} from {source_path}"
                )
                continue

            f_out.write(cleaned_line + "\n")
            written_lines += 1

    return {
        "written_lines": written_lines,
        "skipped_lines": skipped_lines,
    }


@contextmanager
def _ttl_ping_lock(output_dir: str, asn: str):
    os.makedirs(output_dir, exist_ok=True)
    lock_path = os.path.join(output_dir, f".ttl_ping_{asn}.lock")
    lock_handle = open(lock_path, "a+", encoding="utf-8")

    try:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            lock_handle.seek(0)
            owner = lock_handle.read().strip() or "unknown"
            raise RuntimeError(
                f"Another ttl_ping run is already active for {asn} in {output_dir} "
                f"(lock: {lock_path}, owner: {owner})"
            ) from exc

        lock_handle.seek(0)
        lock_handle.truncate()
        lock_handle.write(str(os.getpid()))
        lock_handle.flush()
        yield
    finally:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        finally:
            lock_handle.close()


def _maybe_enqueue_processing_job(
    processing_queue: "queue.Queue | None",
    active_bucket: dict | None,
) -> None:
    if processing_queue is None or active_bucket is None:
        return
    if not active_bucket.get("has_data"):
        return

    snapshot_token = uuid.uuid4().hex
    endpoint_snapshot_path = (
        f"{os.path.splitext(active_bucket['endpoint_output_file'])[0]}"
        f".processing.{snapshot_token}.json"
    )
    sec_last_snapshot_path = (
        f"{os.path.splitext(active_bucket['sec_last_output_file'])[0]}"
        f".processing.{snapshot_token}.json"
    )

    shutil.copyfile(
        active_bucket["endpoint_output_file"],
        endpoint_snapshot_path,
    )
    shutil.copyfile(
        active_bucket["sec_last_output_file"],
        sec_last_snapshot_path,
    )

    processing_queue.put({
        "endpoint_path": endpoint_snapshot_path,
        "sec_last_path": sec_last_snapshot_path,
        "mapping_path": active_bucket["mapping_file"],
        "cleanup_paths": [
            endpoint_snapshot_path,
            sec_last_snapshot_path,
        ],
    })


def _background_processing_worker(processing_queue: "queue.Queue") -> None:
    while True:
        job = processing_queue.get()
        if job is None:
            processing_queue.task_done()
            break

        try:
            filtered_output_path = process_ttl_ping_bucket(
                endpoint_path=job["endpoint_path"],
                sec_last_path=job["sec_last_path"],
                mapping_path=job["mapping_path"],
            )
            print(
                "Processed filtered ttl_ping bucket: "
                f"{filtered_output_path}"
            )
        except Exception as exc:
            print(
                "Background ttl_ping processing failed for "
                f"{job['endpoint_path']}: {exc}"
            )
        finally:
            cleanup_temp_files({
                path: path for path in job.get("cleanup_paths", [])
            })
            processing_queue.task_done()

def ttl_ping(
    asn: str,
    wait_probe: int,
    num_probes: int,
    output_dir: str,
    name: str,
    sl_ep_map_file: str = None,
    ep_sl_file: str = None,
):
    with _ttl_ping_lock(output_dir, asn):
        tmp_output_dir = os.path.join(output_dir, f"tmp_output_{asn}")
        os.makedirs(tmp_output_dir, exist_ok=True)

        #######################################################################
        # Split measurements into batches
        #######################################################################
        infinite_mode = (num_probes == 0)
        batch_size = 300  # <-- tune this (memory vs restart overhead)

        if infinite_mode:
            print("Running in infinite mode (press Ctrl+C to stop)")
            total_batches = float('inf')
        else:
            total_batches = (num_probes + batch_size - 1) // batch_size

        #######################################################################
        # Import second-to-last IPs and endpoint IPs
        #######################################################################
        sl_ep_map_file_tmp, ep_sl_file_tmp  = get_sl_files(name)
        if sl_ep_map_file is None:
            sl_ep_map_file = sl_ep_map_file_tmp

        if ep_sl_file is None:
            ep_sl_file = ep_sl_file_tmp

        #######################################################################
        # Endpoint grouping
        #######################################################################
        endpoint_ip_input_files = get_ep_ips(ep_sl_file)

        #######################################################################
        # Presat grouping
        #######################################################################
        seclast_ip_input_files = get_sl_ips(sl_ep_map_file)

        #######################################################################
        # Batched Streaming Ping Loop
        #######################################################################
        processing_queue: queue.Queue | None = queue.Queue()
        processing_thread = threading.Thread(
            target=_background_processing_worker,
            args=(processing_queue,),
            daemon=True,
        )
        processing_thread.start()

        running_procs = []
        batch_idx = 0
        active_bucket = None
        try:
            while batch_idx < total_batches:
                if infinite_mode:
                    curr_sl_map_file, curr_ep_sl_file = get_sl_files(name)

                    # if there is a new mapping file
                    if curr_sl_map_file != sl_ep_map_file:
                        print(f"new ep to sl mapping: {curr_sl_map_file}")
                        print(f"---> old ep to sl mapping: {sl_ep_map_file}")

                        _maybe_enqueue_processing_job(processing_queue, active_bucket)
                        active_bucket = None

                        sl_ep_map_file = curr_sl_map_file
                        ep_sl_file = curr_ep_sl_file

                        # remove old temp scamper input files
                        cleanup_temp_files(
                            seclast_ip_input_files,
                            endpoint_ip_input_files,
                        )

                        # create new temp scamper input files
                        seclast_ip_input_files = get_sl_ips(sl_ep_map_file)
                        endpoint_ip_input_files = get_ep_ips(ep_sl_file)

                if infinite_mode:
                    this_batch = batch_size
                else:
                    remaining = num_probes - batch_idx * batch_size
                    this_batch = min(batch_size, remaining)

                print(f"[{asn}] Starting batch {batch_idx+1} with {this_batch} probes")

                ################################################################
                # Select output files
                ################################################################
                if infinite_mode:
                    endpoint_output_file = get_time_bucket_file(
                        output_dir,
                        name,
                        "endpoint"
                    )
                    sec_last_output_file = get_time_bucket_file(
                        output_dir,
                        name,
                        "sec_last"
                    )
                else:
                    endpoint_output_file = f"{output_dir}/endpoint.json"
                    sec_last_output_file = f"{output_dir}/sec_last.json"

                if active_bucket is not None and (
                    active_bucket["endpoint_output_file"] != endpoint_output_file
                    or active_bucket["sec_last_output_file"] != sec_last_output_file
                ):
                    _maybe_enqueue_processing_job(processing_queue, active_bucket)
                    active_bucket = None

                if active_bucket is None:
                    active_bucket = {
                        "endpoint_output_file": endpoint_output_file,
                        "sec_last_output_file": sec_last_output_file,
                        "mapping_file": ep_sl_file,
                        "has_data": False,
                    }

                running_procs = []

                ################################################################
                # Spawn endpoint jobs
                ################################################################
                for src_ip, file in endpoint_ip_input_files.items():

                    temp_out = f"{tmp_output_dir}/endpoint_{src_ip}_{uuid.uuid4().hex}.json"

                    cmd = [
                        scamper, "-O", "json", "-o", temp_out, "-p", str(pps),
                        "-c", f"ping -S {src_ip} -c {this_batch} -i {wait_probe}",
                        file
                    ]

                    proc = subprocess.Popen(cmd)

                    running_procs.append({
                        'proc': proc,
                        'type': 'endpoint',
                        'output_file': temp_out,
                    })

                ################################################################
                # Spawn seclast jobs
                ################################################################
                for hop, file in seclast_ip_input_files.items():

                    src_ip = SRC_IPS[hop % len(SRC_IPS)]
                    temp_out = f"{tmp_output_dir}/seclast_{hop}_{uuid.uuid4().hex}.json"

                    cmd = [
                        scamper, "-O", "json", "-o", temp_out, "-p", str(pps),
                        "-c", f"ping -S {src_ip} -c {this_batch} -i {wait_probe} -m {hop}",
                        file
                    ]

                    proc = subprocess.Popen(cmd)

                    running_procs.append({
                        'proc': proc,
                        'type': 'seclast',
                        'output_file': temp_out,
                    })

                ################################################################
                # Wait + Aggregate
                ################################################################
                for p in running_procs:
                    try:
                        p['proc'].wait()
                    except KeyboardInterrupt:
                        print("Ignoring interrupt, continuing experiment...")
                        p['proc'].wait()

                    final_file = (
                        endpoint_output_file
                        if p['type'] == 'endpoint'
                        else sec_last_output_file
                    )

                    append_stats = _append_valid_json_lines(
                        p['output_file'],
                        final_file,
                    )
                    if append_stats["skipped_lines"]:
                        print(
                            "Dropped malformed scamper lines while appending "
                            f"{p['output_file']} -> {final_file}: "
                            f"{append_stats['skipped_lines']} skipped, "
                            f"{append_stats['written_lines']} written"
                        )

                    os.remove(p['output_file'])

                active_bucket["has_data"] = True

                print(f"Finished batch {batch_idx+1}: endpoint file: {endpoint_output_file}, seclast file: {sec_last_output_file}")

                batch_idx += 1

                # Optional small sleep to avoid tight spin in infinite mode
                if infinite_mode:
                    time.sleep(1)
        finally:
            _maybe_enqueue_processing_job(processing_queue, active_bucket)
            processing_queue.put(None)
            processing_queue.join()
            processing_thread.join(timeout=1)
