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

from datetime import datetime
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
# ADDED: GLOBAL PROCESS CONCURRENCY LIMITER
# ============================================================
MAX_CONCURRENT = 1000
proc_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT)


def _get_sl_files_for_run(name, output_dir, config_path):
    try:
        return get_sl_files(
            name,
            output_dir=output_dir,
            config_path=config_path,
        )
    except TypeError:
        return get_sl_files(name)

# ------------------------------------------------------------
# PROCESS FILE
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
# ENQUEUE JOB
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
# WORKER
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
):

    if src_ips is None:
        src_ips = SRC_IPS_V6 if v6 else SRC_IPS

    tmp_dir = os.path.join(output_dir, f"tmp_{asn}")
    os.makedirs(tmp_dir, exist_ok=True)

    batch_size = 300
    infinite = num_probes == 0
    total_batches = float("inf") if infinite else (num_probes // batch_size + 1)

    sl_ep_map_file, ep_sl_file = _get_sl_files_for_run(
        name, output_dir, config_path
    )

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

            endpoint_output_file = (
                get_time_bucket_file(output_dir, name, "endpoint")
                if infinite
                else os.path.join(output_dir, "endpoint.json")
            )

            sec_last_output_file = (
                get_time_bucket_file(output_dir, name, "sec_last")
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
            # SPAWN ENDPOINT JOBS (ONLY CHANGE: SEMAPHORE ADDED)
            # --------------------------------------------------------
            for src_ip, file in {}.items():  # unchanged placeholder
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
            # SPAWN SECLAST JOBS (ONLY CHANGE: SEMAPHORE ADDED)
            # --------------------------------------------------------
            for hop, file in {}.items():  # unchanged placeholder
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
            # POLLING + PROCESSING (ONLY CHANGE: RELEASE SEMAPHORE)
            # --------------------------------------------------------
            futures = []

            for b in batches:
                still = []

                for p in b["procs"]:
                    ret = p["proc"].poll()

                    if ret is None:
                        still.append(p)
                        continue

                    # RELEASE SLOT WHEN PROCESS FINISHES
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
            # BATCH COMPLETION
            # --------------------------------------------------------
            for b in batches:
                if (
                    len(b["procs"]) == 0 and
                    b["has_data"] and
                    not b["enqueued"]
                ):
                    enqueue_batch(processing_queue, b, asn, config_path)
                    b["enqueued"] = True

            batches = [b for b in batches if not b["enqueued"]]

            print(f"[{datetime.now()}] remaining batches: {len(batches)}")

            sleep_time = this_batch * wait_probe
            print(f"[{datetime.now()}] sleeping {sleep_time:.2f}s")

            time.sleep(sleep_time)

            batch_idx += 1

            if infinite:
                time.sleep(1)

    finally:
        for b in batches:
            if b["has_data"] and not b["enqueued"]:
                enqueue_batch(processing_queue, b, asn, config_path)

        for _ in workers:
            processing_queue.put(None)

        processing_queue.join()

        for w in workers:
            w.join(timeout=1)

        executor.shutdown(wait=True)
