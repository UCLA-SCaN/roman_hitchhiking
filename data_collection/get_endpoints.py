import argparse
import pandas as pd
import os
import shutil
import subprocess
from config import ASN, INPUT_IP_FILE

from src.helper import get_day_directory
from run_scamper import run_paris_trs
from parse_scamper import get_last_hops_from_paris_tr

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

    args = parser.parse_args()
    as_num = args.asn if args.asn else ASN[2:]
    input_ip_file = args.ip_file if args.ip_file else INPUT_IP_FILE

    # Output files
    output_dir = get_day_directory()
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

    if not input_ip_file:
        from services_from_censys import get_censys_exposed_services
        censys_df = get_censys_exposed_services(int(as_num))
        censys_df.to_csv(info_file, index=False)
        censys_df[['ip']].to_csv(ip_file, header=None, index=None)
    elif args.ip_file:
        # copy the provided file to your working ip_file location
        shutil.copy(args.ip_file, ip_file)
    else:
        raise ValueError("Must provide either --asn or --ip_file argument")
    
    run_paris_trs(
        ip_file=ip_file, 
        output_file=paris_trs_file,
    )

    sec_to_last_df = get_last_hops_from_paris_tr(
        paris_trs_file, asn_num=as_num
    )

    sec_to_last_df.to_csv(sec_to_last_file, index=False)
    
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
    if args.name:
        cmd.extend(["--name", args.name])
    cmd.extend(["--log", "True"])

    subprocess.run(cmd, check=True, cwd=REPO_ROOT)
