import tempfile
import threading
import queue
import os
import fcntl
import json
import shutil
import pandas as pd
import uuid
import subprocess
import time

from datetime import UTC, datetime, timedelta
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor

from config import DEFAULT_CONFIG_PATH, SRC_IPS, SRC_IPS_V6
from parse_scamper import paris_tr_to_df
from src.helper import ensure_trailing_newline, get_sl_files, get_time_bucket_file
from src.rhh_processing import process_ttl_ping_bucket


scamper = "scamper"
pps = 50000

file_lock = threading.Lock()

# ============================================================
# ADDED: GLOBAL PROCESS LIMIT (ONLY CHANGE)
# ============================================================
MAX_CONCURRENT = 1000
proc_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT)
TIMEOUT = 1800

def run_paris_trs(ip_file: str, output_file: str) -> pd.DataFrame:
    """
    Run an ICMP paris-traceroute to every IP address in a given file.

    :param ip_file: file path string to a new-line delimited list of IPs to run traceroutes to
    :param output_file: file path string to .json file to output traceroute data
    """
    import os as os_module
    
    # Check if input file exists and is not empty
    if not os_module.path.exists(ip_file):
        raise FileNotFoundError(f"Input IP file not found: {ip_file}")
    
    if os_module.path.getsize(ip_file) == 0:
        raise ValueError(f"Input IP file is empty: {ip_file}")

    ensure_trailing_newline(ip_file)

    # Determine if we need sudo (running as non-root)
    needs_sudo = os.getuid() != 0
    sudo_prefix = "sudo " if needs_sudo else ""
    
    cmd_str = f"{sudo_prefix}{scamper} -O json -o {output_file} -p 200 -c \"trace -P icmp-paris -q 1 -g 15 \" -f {ip_file}"
    print(f"Running scamper command: {cmd_str}")
    
    try:
        result = subprocess.run(
                cmd_str, 
                shell=True,
                capture_output=True,
                text=True,
                # timeout=TIMEOUT  # 30 minute timeout
        )
        
        if result.returncode != 0:
            stderr_msg = result.stderr[:500] if result.stderr else "No stderr"
            raise RuntimeError(
                f"Scamper failed with exit code {result.returncode}. "
                f"stderr: {stderr_msg}\n"
                f"This often means: 1) Permission denied (needs root or CAP_NET_RAW), "
                f"2) Invalid IPs in the input file, 3) Network issues."
            )
        
        if result.stderr:
            print(f"Scamper warnings/errors: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Scamper command timed out after {TIMEOUT} seconds")
    except ValueError as e:
        raise ValueError(f"Invalid scamper command: {cmd_str}. Error: {e}")

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

def get_ep_ips(ep_sl_file: str, src_ips: list[str]):
    ep_ip_input_files = {}

    sl_df = pd.read_csv(ep_sl_file)
    eps = sl_df['dst'].unique().tolist()
    print("*" * 80)
    print(f"endpoints: {len(eps)}")

    for i, src_ip in enumerate(src_ips):
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            ep_ip_input_files[src_ip] = tmp.name
            for j, ip in enumerate(eps):
                if j % len(src_ips) == i:
                    tmp.write(ip + '\n')
            ensure_trailing_newline(tmp.name)
            print(f"created temp file for endpoints: {tmp.name}")

    return ep_ip_input_files

def get_sl_ips(mapping_file: str):
    sl_ip_input_files = {}

    try:
        sl_ep_map_df = pd.read_csv(mapping_file)
    except Exception as e:
        print(f"Error reading mapping file {mapping_file}: {e}")
        raise

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
            ensure_trailing_newline(tmp.name)

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


def _get_sl_files_for_run(
    name: str | None,
    output_dir: str,
    config_path: str,
):
    try:
        return get_sl_files(
            name,
            output_dir=output_dir,
            config_path=config_path,
        )
    except TypeError as exc:
        if "unexpected keyword argument" not in str(exc):
            raise
        return get_sl_files(name)

# ------------------------------------------------------------
# ORIGINAL HELPERS (UNCHANGED)
# ------------------------------------------------------------
def get_ep_ips(ep_sl_file: str, src_ips: list[str]):
    ep_ip_input_files = {}

    sl_df = pd.read_csv(ep_sl_file)
    eps = sl_df['dst'].unique().tolist()

    print("*" * 80)
    print(f"endpoints: {len(eps)}")

    for i, src_ip in enumerate(src_ips):
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            ep_ip_input_files[src_ip] = tmp.name
            for j, ip in enumerate(eps):
                if j % len(src_ips) == i:
                    tmp.write(ip + '\n')

            ensure_trailing_newline(tmp.name)
            print(f"created temp endpoint file: {tmp.name}")

    return ep_ip_input_files


def get_sl_ips(mapping_file: str):
    sl_ip_input_files = {}

    df = pd.read_csv(mapping_file)

    grouped = (
        df.groupby('sl_hop')['ep_ip']
        .apply(set)
        .reset_index()
    )

    print("*" * 80)
    print(f"second-to-last: {len(df)}")

    for _, row in grouped.iterrows():
        hop = int(row['sl_hop'])

        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            sl_ip_input_files[hop] = tmp.name

            for ip in row['ep_ip']:
                tmp.write(ip + '\n')

            ensure_trailing_newline(tmp.name)

    return sl_ip_input_files


# ------------------------------------------------------------
# PROCESS FILE (UNCHANGED LOGIC)
# ------------------------------------------------------------
def process_file(p, endpoint_output_file, sec_last_output_file):
    final_file = (
        endpoint_output_file
        if p["type"] == "endpoint"
        else sec_last_output_file
    )

    valid = []
    skipped = 0

    with open(p["output_file"], "r") as f:
        for line in f:
            try:
                json.loads(line)
                valid.append(line)
            except json.JSONDecodeError:
                skipped += 1

    with file_lock:
        with open(final_file, "a") as out:
            out.writelines(valid)

    try:
        os.remove(p["output_file"])
    except:
        pass

    return {"written": len(valid), "skipped": skipped}


# ------------------------------------------------------------
# ENQUEUE JOB (UNCHANGED)
# ------------------------------------------------------------
def enqueue_batch(processing_queue, batch, asn, config_path):
    ep = batch["endpoint_file"]
    sl = batch["sec_last_file"]

    if not (os.path.exists(ep) and os.path.exists(sl)):
        return

    if os.path.getsize(ep) == 0 or os.path.getsize(sl) == 0:
        return

    token = uuid.uuid4().hex
    ep_snap = f"{ep}.processing.{token}.json"
    sl_snap = f"{sl}.processing.{token}.json"

    with file_lock:
        shutil.copyfile(ep, ep_snap)
        shutil.copyfile(sl, sl_snap)

    processing_queue.put({
        "endpoint_path": ep_snap,
        "sec_last_path": sl_snap,
        "mapping_path": batch["mapping"],
        "allowed_sec_last_asn": asn,
        "config_path": config_path,
        "cleanup_paths": [ep_snap, sl_snap],
    })


# ------------------------------------------------------------
# WORKER (UNCHANGED)
# ------------------------------------------------------------
def worker(processing_queue):
    while True:
        job = processing_queue.get()
        if job is None:
            processing_queue.task_done()
            break

        try:
            out = process_ttl_ping_bucket(
                endpoint_path=job["endpoint_path"],
                sec_last_path=job["sec_last_path"],
                mapping_path=job["mapping_path"],
                allowed_sec_last_asn=job["allowed_sec_last_asn"],
                config_path=job["config_path"],
            )
            print(f"[WORKER] processed: {out}")

        except Exception as e:
            print(f"[WORKER ERROR] {e}")

        finally:
            for p in job["cleanup_paths"]:
                try:
                    os.remove(p)
                except:
                    pass

            processing_queue.task_done()


# ------------------------------------------------------------
# MAIN LOOP
# ------------------------------------------------------------
def ttl_ping(
    asn,
    wait_probe,
    num_probes,
    output_dir,
    name,
    sl_ep_map_file=None,
    ep_sl_file=None,
    v6=False,
    config_path=DEFAULT_CONFIG_PATH,
    src_ips=None,
    skip_processing=False,
):

    if src_ips is None:
        src_ips = SRC_IPS_V6 if v6 else SRC_IPS

    tmp_dir = os.path.join(output_dir, f"tmp_{asn}")
    os.makedirs(tmp_dir, exist_ok=True)

    batch_size = 600
    batch_interval_seconds = batch_size * wait_probe
    batch_interval = timedelta(seconds=batch_interval_seconds)
    infinite = num_probes == 0
    total_batches = float("inf") if infinite else (num_probes // batch_size + 1)
    scheduled_bucket_time = None
    next_batch_start = time.monotonic()

    sl_ep_map_file, ep_sl_file = _get_sl_files_for_run(
        name, output_dir, config_path
    )

    # ✅ RESTORED (CRITICAL)
    endpoint_ip_input_files = get_ep_ips(ep_sl_file, src_ips=src_ips)
    seclast_ip_input_files = get_sl_ips(sl_ep_map_file)

    processing_queue = None
    workers = []

    if not skip_processing:
        processing_queue = queue.Queue()
        workers = [
            threading.Thread(target=worker, args=(processing_queue,), daemon=True)
            for _ in range(4)
        ]
        for w in workers:
            w.start()

    executor = ThreadPoolExecutor(max_workers=8)

    batches = []

    try:
        batch_idx = 0

        while batch_idx < total_batches:

            print(f"\n[{datetime.now()}] Batch {batch_idx} starting")

            this_batch = batch_size
            if infinite and scheduled_bucket_time is None:
                now = datetime.now(UTC)
                minute_bucket = (now.minute // 10) * 10
                scheduled_bucket_time = now.replace(
                    minute=minute_bucket,
                    second=0,
                    microsecond=0,
                )

            endpoint_output_file = (
                get_time_bucket_file(
                    output_dir,
                    name,
                    "endpoint",
                    bucket_time=scheduled_bucket_time,
                )
                if infinite
                else os.path.join(output_dir, "endpoint.json")
            )

            sec_last_output_file = (
                get_time_bucket_file(
                    output_dir,
                    name,
                    "sec_last",
                    bucket_time=scheduled_bucket_time,
                )
                if infinite
                else os.path.join(output_dir, "sec_last.json")
            )

            print(f"\tendpoint: {endpoint_output_file}")
            print(f"\tsec_last: {sec_last_output_file}")

            batch = {
                "procs": [],
                "endpoint_file": endpoint_output_file,
                "sec_last_file": sec_last_output_file,
                "mapping": ep_sl_file,
                "has_data": False,
                "enqueued": False,
            }

            # --------------------------------------------------------
            # SPAWN ENDPOINT JOBS
            # --------------------------------------------------------
            for src_ip, file in endpoint_ip_input_files.items():
                out = f"{tmp_dir}/ep_{uuid.uuid4().hex}.json"

                proc_semaphore.acquire()
                proc = subprocess.Popen([
                    scamper, "-O", "json", "-o", out,
                    "-p", str(pps),
                    "-c", f"ping -S {src_ip} -c {this_batch} -i {wait_probe}",
                    file
                ])

                batch["procs"].append({
                    "proc": proc,
                    "type": "endpoint",
                    "output_file": out
                })

            # --------------------------------------------------------
            # SPAWN SECLAST JOBS
            # --------------------------------------------------------
            for hop, file in seclast_ip_input_files.items():
                out = f"{tmp_dir}/sl_{uuid.uuid4().hex}.json"

                proc_semaphore.acquire()
                proc = subprocess.Popen([
                    scamper, "-O", "json", "-o", out,
                    "-p", str(pps),
                    "-c", f"ping -S {src_ips[hop % len(src_ips)]} -c {this_batch} -i {wait_probe} -m {int(hop)}",
                    file
                ])

                batch["procs"].append({
                    "proc": proc,
                    "type": "seclast",
                    "output_file": out
                })

            batches.append(batch)

            # --------------------------------------------------------
            # POLL + PROCESS
            # --------------------------------------------------------
            futures = []

            for b in batches:
                still = []

                for p in b["procs"]:
                    ret = p["proc"].poll()

                    if ret is None:
                        still.append(p)
                        continue

                    proc_semaphore.release()

                    if ret != 0:
                        print(f"[WARN] failed process: {ret}")
                        continue

                    futures.append(
                        executor.submit(
                            process_file,
                            p,
                            b["endpoint_file"],
                            b["sec_last_file"]
                        )
                    )

                    b["has_data"] = True

                b["procs"] = still

            for f in futures:
                f.result()

            # --------------------------------------------------------
            # ENQUEUE COMPLETED BATCHES
            # --------------------------------------------------------
            for b in batches:
                if (
                    len(b["procs"]) == 0 and
                    b["has_data"] and
                    not b["enqueued"]
                ):
                    if skip_processing:
                        print("[INFO] batch complete → skipping merged_filtered processing")
                    else:
                        print(f"[INFO] batch complete → enqueue")
                        enqueue_batch(processing_queue, b, asn, config_path)
                    b["enqueued"] = True

            batches = [b for b in batches if not b["enqueued"]]

            print(f"[{datetime.now()}] remaining batches: {len(batches)}")

            next_batch_start += batch_interval_seconds
            sleep_time = max(0, next_batch_start - time.monotonic())
            print(f"[{datetime.now()}] sleeping {sleep_time:.2f}s")

            time.sleep(sleep_time)

            batch_idx += 1

            if infinite:
                scheduled_bucket_time += batch_interval

    finally:
        for b in batches:
            if b["has_data"] and not b["enqueued"]:
                if skip_processing:
                    b["enqueued"] = True
                else:
                    enqueue_batch(processing_queue, b, asn, config_path)

        if processing_queue is not None:
            for _ in workers:
                processing_queue.put(None)

            processing_queue.join()

            for w in workers:
                w.join(timeout=1)

        executor.shutdown(wait=True)
