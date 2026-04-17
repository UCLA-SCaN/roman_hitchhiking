import argparse
import urllib
import pandas as pd
import json
import bz2
import os
import subprocess

from src.helper import get_day_directory
from src.helper import ensure_trailing_newline
from config import get_runtime_settings
from run_scamper import run_paris_trs
from parse_scamper import get_last_hops_from_paris_tr

DATA_COLLECTION_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(DATA_COLLECTION_DIR)
VENV_PYTHON = os.path.join(DATA_COLLECTION_DIR, "venv", "bin", "python3")
RIPE_CONFIG_PATH = os.path.join(DATA_COLLECTION_DIR, "config_ripe.ini")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect RIPE Atlas anchor data")
    parser.add_argument(
        "--config",
        type=str,
        default=RIPE_CONFIG_PATH,
        help="Path to the config.ini file.",
    )
    args = parser.parse_args()
    settings = get_runtime_settings(args.config)

    # Output files
    output_dir = get_day_directory(
        output_dir=settings["output_dir"],
        config_path=args.config,
    )

    ripe_info_file = os.path.join(output_dir, 'ripe_info.csv')
    ripe_ip_file = os.path.join(output_dir, 'ripe_ips.txt')
    ripe_paris_trs_file = os.path.join(output_dir, 'ripe_paris_trs.json')
    ripe_sec_to_last_file = os.path.join(output_dir, 'ripe_sec_to_last.csv')
    ripe_sl_mapping_file = os.path.join(output_dir, 'ripe_sl_mapping.csv')
    
    # Request RIPE Atlas anchors
    probes = urllib.request.urlopen('https://ftp.ripe.net/ripe/atlas/probes/archive/meta-latest')
    probes = json.load(bz2.open(probes))
    probedf = pd.DataFrame(probes['objects'])

    probedf = probedf[probedf.status == 1].dropna(subset=['address_v4'])
    probedf[probedf.is_anchor == True].to_csv(ripe_info_file, index=False)

    pd.read_csv(ripe_info_file)[['address_v4']].to_csv(
        ripe_ip_file,
        index=False,
        header=False,
    )
    ensure_trailing_newline(ripe_ip_file)

    # Run Paris Traceroutes to RIPE Atlas anchors
    run_paris_trs(
        ip_file=ripe_ip_file, 
        output_file=ripe_paris_trs_file,
    )

    sec_to_last_df = get_last_hops_from_paris_tr(
        ripe_paris_trs_file, asn_num='CONTROL', sat_hop=settings["sat_hop"]
    )

    sec_to_last_df.to_csv(ripe_sec_to_last_file, index=False)

    cmd = [
        "sudo",
        VENV_PYTHON,
        "-m",
        "data_collection.src.sl_mapping",
        "--name", "ripe",
        "--input", ripe_sec_to_last_file,
        "--output", ripe_sl_mapping_file,
        "--config", args.config,
        "--log", "True",
    ]

    subprocess.run(cmd, check=True, cwd=REPO_ROOT)
