import argparse
import pandas as pd
import subprocess
import json
import os
import tempfile

try:
    from ..config import OUTPUT_DIR, SRC_IPS
    from .helper import find_latest_sec_last, get_day_directory
except ImportError:
    from config import OUTPUT_DIR, SRC_IPS
    from helper import find_latest_sec_last, get_day_directory

"""
"""
# -----------------------------
# CONFIG
# -----------------------------
scamper = "scamper"
pps = 5000
wait_probe = 1
this_batch = 5

parser = argparse.ArgumentParser(description="Starlink mapping via scamper")

parser.add_argument(
    "--name", 
    required=False, default=None,
    help="Name of measurement", 
)
parser.add_argument("--input", help="Path to sec_to_last.csv")
parser.add_argument("--output", help="Output CSV file")
parser.add_argument("--log", help="Output CSV file", default=False)

args = parser.parse_args()

# assign
sec_last_path = args.input or find_latest_sec_last(
    OUTPUT_DIR,
    f"{args.name}_sec_to_last.csv" if args.name else "sec_to_last.csv",
)
output_file = args.output or os.path.join(
    get_day_directory(),
    f"{args.name}_sl_mapping.csv" if args.name else "sl_mapping.csv",
)

# -----------------------------
# LOAD DATA
# -----------------------------
sec_last_df = pd.read_csv(sec_last_path)

agg_df = sec_last_df.groupby('sec_last_ip').agg({
    'dst': lambda x: list(x),
    'sec_last_hop': lambda x: list(x),
}).reset_index()

# track final results
results = []

# track which sl_ip already succeeded (so we skip them later)
resolved_sl_ips = set()

# -----------------------------
# MAIN LOOP SETUP
# -----------------------------
agg_df['num_dst'] = agg_df['dst'].apply(len)
max_len = agg_df['num_dst'].max()

# -----------------------------
# MAIN LOOP
# -----------------------------
for i in range(max_len):

    if args.log:
        print(f"\n=== ITERATION {i} ===")

    selected_pairs_data = []

    # -----------------------------------
    # 1. select i-th candidate per sl_ip
    # -----------------------------------
    for _, row in agg_df.iterrows():
        sl_ip = row['sec_last_ip']

        # skip if already resolved
        if sl_ip in resolved_sl_ips:
            continue

        if i < len(row['dst']):
            selected_pairs_data.append({
                'ep_ip': row['dst'][i],
                'sl_ip': sl_ip,
                'sl_hop': row['sec_last_hop'][i],
            })

    if not selected_pairs_data:
        continue

    selected_pairs_df = pd.DataFrame(selected_pairs_data)

    # -----------------------------------
    # 2. group by hop
    # -----------------------------------
    pairs_grouped_df = (
        selected_pairs_df
        .groupby('sl_hop')
        .agg({
            'ep_ip': list,
            'sl_ip': list,
        })
        .reset_index()
    )

    # -----------------------------------
    # 3. run scamper per hop
    # -----------------------------------
    for _, row in pairs_grouped_df.iterrows():
        hop = row['sl_hop']
        ep_ips = row['ep_ip']
        sl_ips = row['sl_ip']

        if args.log:
            print(f"Processing hop={hop} with {len(ep_ips)} targets")

        # map ep_ip → expected sl_ip
        expected_map = dict(zip(ep_ips, sl_ips))

        # -----------------------------
        # create temp input file
        # -----------------------------
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            for ip in ep_ips:
                f.write(ip + '\n')
            input_file = f.name

        # -----------------------------
        # temp output file
        # -----------------------------
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            temp_out = tmp.name

        # choose a source IP (round-robin optional)
        src_ip = SRC_IPS[i % len(SRC_IPS)]

        cmd = [
            scamper, "-O", "json", "-o", temp_out, "-p", str(pps),
            "-c", f"ping -S {src_ip} -c {this_batch} -i {wait_probe} -m {hop}",
            input_file
        ]

        try:
            proc = subprocess.Popen(cmd)
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            print("Timeout")
            os.remove(input_file)
            os.remove(temp_out)
            continue

        # -----------------------------
        # parse output
        # -----------------------------
        success = 0
        failure = 0

        try:
            with open(temp_out, 'r') as f:
                for line in f:
                    data = json.loads(line)

                    if data.get("type") != "ping":
                        continue

                    dst = data.get("dst")
                    responses = data.get("responses", [])

                    if not responses:
                        failure += 1
                        continue

                    responder_ip = responses[0].get("from")
                    expected_sl_ip = expected_map.get(dst)

                    if responder_ip == expected_sl_ip:
                        success += 1

                        results.append({
                            "sl_ip": expected_sl_ip,
                            "ep_ip": dst,
                            "sl_hop": hop
                        })

                        # mark as resolved so we stop probing it
                        resolved_sl_ips.add(expected_sl_ip)

                    else:
                        failure += 1

        except Exception as e:
            print("Parsing error:", e)

        if args.log:
            print(f"Hop {hop}: success={success}, failure={failure}")

        # cleanup
        os.remove(input_file)
        os.remove(temp_out)

# -----------------------------
# SAVE RESULTS
# -----------------------------
mapping_df = pd.DataFrame(results)
mapping_df.to_csv(output_file, index=False)

print("\nDone.")
print(f"Total mappings found: {len(mapping_df)}")
