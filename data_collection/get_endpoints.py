import argparse
import pandas as pd
import os
import shutil
import subprocess
from pathlib import Path
from config import DEFAULT_CONFIG_PATH, get_runtime_settings

from parse_scamper import get_last_hops_from_paris_tr
from run_scamper import run_paris_trs
from src.helper import ensure_trailing_newline, get_day_directory
from src.probe_analysis import build_dataframe, compute_ips_to_keep, write_ips_to_csv

DATA_COLLECTION_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(DATA_COLLECTION_DIR)
VENV_PYTHON = os.path.join(DATA_COLLECTION_DIR, "venv", "bin", "python3")
PPS = 50000
RATES = [1, 0.5, 0.2, 0.1]
MAX_PROBE_IPS_PER_FILE = 5000


def split_ip_file_into_batches(
    input_ip_file: str,
    output_dir: str,
    batch_size: int = MAX_PROBE_IPS_PER_FILE,
) -> list[Path]:
    input_path = Path(input_ip_file)
    batch_dir = Path(output_dir) / "test_probes" / "ip_batches"
    batch_dir.mkdir(parents=True, exist_ok=True)

    ips = [
        line.strip()
        for line in input_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not ips:
        return []

    batch_files: list[Path] = []
    total_batches = (len(ips) + batch_size - 1) // batch_size

    for batch_index, start in enumerate(range(0, len(ips), batch_size), start=1):
        batch_ips = ips[start:start + batch_size]
        batch_file = batch_dir / f"{input_path.stem}_part_{batch_index:04d}.txt"
        batch_file.write_text("\n".join(batch_ips) + "\n", encoding="utf-8")
        batch_files.append(batch_file)

    print(
        f"Split {len(ips)} IPs into {total_batches} batch file(s) "
        f"with up to {batch_size} IPs each"
    )
    return batch_files

def run_test_probes(input_ip_file: str, output_dir: str, name: str | None) -> list[Path]:
    ensure_trailing_newline(input_ip_file)

    input_path = Path(input_ip_file)
    probe_output_dir = Path(output_dir) / "test_probes"
    probe_output_dir.mkdir(parents=True, exist_ok=True)

    output_stem = input_path.stem if not name else f"{name}_{input_path.stem}"
    generated_output_files: list[Path] = []

    for rate in RATES:
        count = int(10 / rate)
        rate_str = str(rate)
        output_file = probe_output_dir / f"{output_stem}_rate_{rate_str}_test_probe.json"

        cmd = [
            "sudo",
            "scamper",
            "-O",
            "json",
            "-o",
            str(output_file),
            "-p",
            str(PPS),
            "-c",
            f"ping -c {count} -i {rate}",
            str(input_path),
        ]

        print("Running probe command:", " ".join(cmd))
        subprocess.run(cmd, check=True)
        generated_output_files.append(output_file)

    return generated_output_files


def filter_censys_ips(
    raw_ip_file: str,
    filtered_ip_file: str,
    output_dir: str,
    name: str | None,
) -> list[str]:
    batch_files = split_ip_file_into_batches(
        input_ip_file=raw_ip_file,
        output_dir=output_dir,
    )
    generated_output_files: list[Path] = []

    for batch_index, batch_file in enumerate(batch_files, start=1):
        print(f"Running test probes for batch {batch_index}/{len(batch_files)}: {batch_file}")
        generated_output_files.extend(
            run_test_probes(
                input_ip_file=str(batch_file),
                output_dir=output_dir,
                name=name,
            )
        )

    rows = build_dataframe(generated_output_files)
    ips_to_keep = compute_ips_to_keep(rows)
    write_ips_to_csv(ips_to_keep, Path(filtered_ip_file))
    ensure_trailing_newline(filtered_ip_file)
    return ips_to_keep

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
    raw_censys_ip_file = os.path.join(
        output_dir,
        'censys_ips.txt' if not args.name else f"{args.name}_censys_ips.txt",
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
        censys_df = get_censys_exposed_services(
            int(as_num),
            bq_project_id=settings["bq_project_id"],
            config_path=args.config,
        )
        print(f"Original number of IPs found from Censys: {len(censys_df)}")
        censys_df.to_csv(info_file, index=False)
        censys_df[['ip']].to_csv(raw_censys_ip_file, header=None, index=None)
        ensure_trailing_newline(raw_censys_ip_file)
        ips_to_keep = filter_censys_ips(
            raw_ip_file=raw_censys_ip_file,
            filtered_ip_file=ip_file,
            output_dir=output_dir,
            name=args.name,
        )
        print(f"Filtered number of IPs to keep: {len(ips_to_keep)}")
    elif input_ip_file:
        # copy the provided file to your working ip_file location
        shutil.copy(input_ip_file, ip_file)
        ensure_trailing_newline(ip_file)
    else:
        raise ValueError("Must provide either --asn or --ip_file argument")
    
    run_paris_trs(
        ip_file=ip_file, 
        output_file=paris_trs_file,
    )

    sec_to_last_df = get_last_hops_from_paris_tr(
        paris_trs_file, asn_num=as_num, sat_hop=settings["sat_hop"]
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
    if args.v6:
        cmd.extend(["--v6", "True"])

    print("Running command:", " ".join(cmd))

    if args.name:
        cmd.extend(["--name", args.name])
    cmd.extend(["--config", args.config])
    cmd.extend(["--log", "True"])

    subprocess.run(cmd, check=True, cwd=REPO_ROOT)
