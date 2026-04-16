import argparse
import pandas as pd
import os
import shutil
import subprocess
from config import DEFAULT_CONFIG_PATH, get_runtime_settings

from src.helper import get_day_directory

DATA_COLLECTION_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(DATA_COLLECTION_DIR)
VENV_PYTHON = os.path.join(DATA_COLLECTION_DIR, "venv", "bin", "python3")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Find endpoints and the hops before")
    parser.add_argument(
        "--asn",
        type=str,
        help="ASN number. Example: for AS12345, provide 12345 as the argument.",
        default=None,
    )
    parser.add_argument(
        "--ip_file",
        type=str,
        help="File containing IP addresses to run Paris Traceroutes on.",
        default=None,
    )
    parser.add_argument(
        "--name",
        type=str,
        help="Name of measurement.",
        default=None,
    )

    parser.add_argument(
        "--v6",
        type=bool,
        default=False,
        help="Whether to use IPv6 addresses (from config) instead of IPv4."
    )

    parser.add_argument(
        "--config",
        type=str,
        default=DEFAULT_CONFIG_PATH,
        help="Path to the config.ini file.",
    )

    args = parser.parse_args()
    settings = get_runtime_settings(args.config)
    as_num = args.asn if args.asn else settings["asn"][2:]
    input_ip_file = args.ip_file if args.ip_file else settings["input_ip_file"]

    # Output files
    output_dir = get_day_directory(
        output_dir=settings["output_dir"],
        config_path=args.config,
    )
    info_file = os.path.join(
        output_dir, 
        'info.csv' if not args.name else f"{args.name}_info.csv",
    )
    ip_file = os.path.join(
        output_dir, 
        'ips.txt' if not args.name else f"{args.name}_ips.txt",
    )
    paris_trs_file = os.path.join(
        output_dir, 
        'paris_trs.json' if not args.name else f"{args.name}_paris_trs.json",
    )
    sec_to_last_file = os.path.join(
        output_dir, 
        'sec_to_last.csv' if not args.name else f"{args.name}_sec_to_last.csv",
    )
    
    # get second-to-last IP mapping
    cmd = [
        "sudo",
        VENV_PYTHON,
        "-m",
        "data_collection.src.sl_mapping",
        "--input", sec_to_last_file,
        "--output", os.path.join(
            output_dir,
            "sl_mapping.csv" if not args.name else f"{args.name}_sl_mapping.csv",
        ),
    ]
    if args.v6:
        cmd.append("--v6")

    print("Running command:", " ".join(cmd))

    if args.name:
        cmd.extend(["--name", args.name])
    cmd.extend(["--config", args.config])
    cmd.extend(["--log", "True"])

    subprocess.run(cmd, check=True, cwd=REPO_ROOT)
