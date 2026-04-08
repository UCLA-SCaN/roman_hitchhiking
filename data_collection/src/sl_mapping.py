import argparse
import pandas as pd
import subprocess
import json
import os
import tempfile

try:
    from ..config import DEFAULT_CONFIG_PATH, get_runtime_settings
    from .helper import find_latest_sec_last, get_day_directory
except ImportError:
    from config import DEFAULT_CONFIG_PATH, get_runtime_settings
    from helper import find_latest_sec_last, get_day_directory

# -----------------------------
# CONFIG
# -----------------------------
scamper = "scamper"
pps = 5000
wait_probe = 1
this_batch = 5

def main():
    parser = argparse.ArgumentParser(description="Starlink mapping via scamper")

    parser.add_argument(
        "--name",
        required=False, default=None,
        help="Name of measurement",
    )
    parser.add_argument("--input", help="Path to sec_to_last.csv")
    parser.add_argument("--output", help="Output CSV file")
    parser.add_argument("--log", help="Output CSV file", default=False)
    parser.add_argument("--v6", help="IPv6 addresses", default=False)
    parser.add_argument(
        "--config",
        type=str,
        default=DEFAULT_CONFIG_PATH,
        help="Path to the config.ini file.",
    )

    args = parser.parse_args()
    settings = get_runtime_settings(args.config)
    src_ips = settings["src_ips_v6"] if args.v6 else settings["src_ips"]
    output_dir = settings["output_dir"]

    sec_last_path = args.input or find_latest_sec_last(
        output_dir,
        f"{args.name}_sec_to_last.csv" if args.name else "sec_to_last.csv",
    )
    output_file = args.output or os.path.join(
        get_day_directory(output_dir=output_dir, config_path=args.config),
        f"{args.name}_sl_mapping.csv" if args.name else "sl_mapping.csv",
    )

    sec_last_df = pd.read_csv(sec_last_path)

    agg_df = sec_last_df.groupby('sec_last_ip').agg({
        'dst': lambda x: list(x),
        'sec_last_hop': lambda x: list(x),
    }).reset_index()

    results = []
    resolved_sl_ips = set()

    agg_df['num_dst'] = agg_df['dst'].apply(len)
    max_len = agg_df['num_dst'].max()

    for i in range(max_len):
        if args.log:
            print(f"\n=== ITERATION {i} ===")

        selected_pairs_data = []

        for _, row in agg_df.iterrows():
            sl_ip = row['sec_last_ip']

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

        pairs_grouped_df = (
            selected_pairs_df
            .groupby('sl_hop')
            .agg({
                'ep_ip': list,
                'sl_ip': list,
            })
            .reset_index()
        )

        for _, row in pairs_grouped_df.iterrows():
            hop = row['sl_hop']
            ep_ips = row['ep_ip']
            sl_ips = row['sl_ip']

            if args.log:
                print(f"Processing hop={hop} with {len(ep_ips)} targets")

            expected_map = dict(zip(ep_ips, sl_ips))

            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                for ip in ep_ips:
                    f.write(ip + '\n')
                input_file = f.name

            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                temp_out = tmp.name

            src_ip = src_ips[i % len(src_ips)]

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
                print(f"Timeout: {cmd}")
                os.remove(input_file)
                os.remove(temp_out)
                continue
            except Exception as e:
                print(f"Error running command {cmd}: {e}")
                os.remove(input_file)
                os.remove(temp_out)
                continue

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

                            resolved_sl_ips.add(expected_sl_ip)

                        else:
                            failure += 1

            except Exception as e:
                print("Parsing error:", e)

            if args.log:
                print(f"Hop {hop}: success={success}, failure={failure}")

            os.remove(input_file)
            os.remove(temp_out)

    mapping_df = pd.DataFrame(results)
    mapping_df.to_csv(output_file, index=False)

    print("\nDone.")
    print(f"Total mappings found: {len(mapping_df)}")


if __name__ == "__main__":
    main()
