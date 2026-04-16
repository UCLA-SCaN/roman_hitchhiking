import argparse
import os
import requests
import subprocess
import json
import re

from config import get_runtime_settings
from src.helper import get_day_directory
from run_scamper import run_paris_trs
from parse_scamper import get_last_hops_from_paris_tr

DATA_COLLECTION_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(DATA_COLLECTION_DIR)
VENV_PYTHON = os.path.join(DATA_COLLECTION_DIR, "venv", "bin", "python3")
RIPE_STARLINK_CONFIG_PATH = os.path.join(DATA_COLLECTION_DIR, "config_ripe_starlink.ini")

if __name__ == "__main__":
    ###########################################################################
    # Setup and configuration
    ###########################################################################
    # Get arguments
    parser = argparse.ArgumentParser(description="Collect RIPE Atlas anchor data")
    parser.add_argument(
        "--config",
        type=str,
        default=RIPE_STARLINK_CONFIG_PATH,
        help="Path to the config.ini file.",
    )
    args = parser.parse_args()
    settings = get_runtime_settings(args.config)

    # Output files
    output_dir = get_day_directory(
        output_dir=settings["output_dir"],
        config_path=args.config,
    )

    # All Starlink IPs RIPE Atlas probes
    ripe_starlink_all_ip_file = os.path.join(output_dir, 'ripe_starlink_all_ips.txt')
    # Responsive Starlink IPs RIPE Atlas probes
    ripe_starlink_ip_file = os.path.join(output_dir, 'ripe_starlink_ips.txt')
    ripe_starlink_paris_trs_file = os.path.join(output_dir, 'ripe_starlink_paris_trs.json')
    ripe_starlink_sec_to_last_file = os.path.join(output_dir, 'ripe_starlink_sec_to_last.csv')
    ripe_starlink_sl_mapping_file = os.path.join(output_dir, 'ripe_starlink_sl_mapping.csv')

    ###########################################################################
    # Get Responsive IPs
    ###########################################################################
    # Query the RIPE Atlas API for probes with ASN 14593
    url = "https://atlas.ripe.net/api/v2/probes/?asn=14593"
    ips = []
    while url:
        response = requests.get(url)
        data = response.json()
        for probe in data.get('results', []):
            if 'address_v4' in probe and probe['address_v4']:
                ips.append(probe['address_v4'])
        url = data.get('next')  # For pagination

    print(f"Found {len(ips)} IPv4 addresses.")

    # Write IPs to a file
    with open(ripe_starlink_all_ip_file, 'w') as f:
        for ip in ips:
            f.write(ip + '\n')

    # Ping all IPs concurrently using scamper for 15 seconds each (15 pings with 1s interval)
    print("Running scamper to ping all IPs...")
    cmd = f"sudo scamper -p 250 -c 'ping -c 15 -i 1' -f {ripe_starlink_all_ip_file} -O json"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)  # Timeout for the whole process
        output = result.stdout
        if result.returncode != 0:
            print("Scamper process error (exit code {}):".format(result.returncode))
            print(result.stderr)
    except subprocess.TimeoutExpired:
        print("Scamper timed out.")
        output = ""

    # Parse JSON output for responsive IPs
    responsive_ips = set()
    for line in output.strip().split('\n'):
        if line:
            try:
                data = json.loads(line)
                if data.get('type') == 'ping' and 'responses' in data and data['responses']:
                    responsive_ips.add(data['dst'])
            except json.JSONDecodeError:
                print(f"Failed to parse JSON line: {line}")

    if not responsive_ips:
        print("No responsive IPs found. First 1000 characters of scamper output:")
        print(repr(output[:1000]))

    print("Responsive IPs:")
    with open(ripe_starlink_ip_file, 'w') as f:
        for ip in sorted(responsive_ips):
            f.write(ip + '\n')
            print(ip)

    ###########################################################################
    # Paris Traceroutes and Second-to-Last Mapping
    ###########################################################################
    run_paris_trs(
        ip_file=ripe_starlink_ip_file, 
        output_file=ripe_starlink_paris_trs_file,
    )

    sec_to_last_df = get_last_hops_from_paris_tr(
        ripe_starlink_paris_trs_file, asn_num=settings["asn"][2:]
    )

    sec_to_last_df.to_csv(ripe_starlink_sec_to_last_file, index=False)

    cmd = [
        "sudo",
        VENV_PYTHON,
        "-m",
        "data_collection.src.sl_mapping",
        "--name", "ripe",
        "--input", ripe_starlink_sec_to_last_file,
        "--output", ripe_starlink_sl_mapping_file,
        "--config", args.config,
        "--log", "True",
    ]

    subprocess.run(cmd, check=True, cwd=REPO_ROOT)

    
    