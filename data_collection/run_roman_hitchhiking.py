import argparse
import os
import pandas as pd
from datetime import datetime
from config import STARLINK_ASN
from run_scamper import Grouping, modified_concurrent_ttl_ping_by_grouping, run_paris_trs
from parse_scamper import get_last_hops_from_paris_tr

"""
Runs Roman HitchHiking
"""

def run_roman_hitchhiking(
        asn: str,
        probe_interval: int,
        num_probes: int,
        output_dir: str,
        multiple_src_ips: bool = True,
        grouping: Grouping = None,
        sample_size: int = None,
        slash: int = None,
        exposed_ips_file: str = None,
):
    """
    :param asn: the autonomous system number formatted as "AS####"
    :param probe_interval: the number of seconds between each probe
    :param num_probes: total number of probes to send to each endpoint, 
                       if 0, continuously send probes every probe_interval
    :param output_dir: output directory
    :param multiple_src_ips: whether or not to use multiple source IPs
    :param grouping: specify grouping
    :param sample_size: sample size
    :param slash: subnet
    :param exposed_services_file: file to use for exposed services
    """
    as_num = asn[2:]

    # get exposed services
    if exposed_ips_file is None:
        from services_from_censys import get_censys_exposed_services
        censys_exposed_services_file = f"{output_dir}/censys_exposed_services_{asn}.csv"
        exposed_ips_file = f"{output_dir}/censys_exposed_ips_{asn}.txt"
        if os.path.exists(censys_exposed_services_file):
            print(f"file exists: {censys_exposed_services_file}")
            censys_df = pd.read_csv(censys_exposed_services_file)
        else:
            print(f"file doesn't exist: {censys_exposed_services_file}")
            print("----querying Censys for exposed services")
            censys_df = get_censys_exposed_services(int(as_num))
            censys_df.to_csv(censys_exposed_services_file)
            censys_df[['ip']].to_csv(exposed_ips_file, header=None, index=None)
            print("----done querying Censys for exposed services")

    # paris traceroute all exposed services
    paris_tr_file = f"{output_dir}/paris_tr_{asn}"
    sec_to_last_file = f"{output_dir}/sec_last_{asn}.csv"
    if os.path.exists(f"{sec_to_last_file}"):
        print(f"file exists: {paris_tr_file}.csv")
        # find second-to-last hops
        sec_to_last_df = pd.read_csv(sec_to_last_file)
    else:
        print(f"file doesn't exists: {paris_tr_file}.csv")
        if not os.path.exists(f"{paris_tr_file}.json"):
            print("----running paris traceroutes")
            paris_tr_df = run_paris_trs(exposed_ips_file, f"{paris_tr_file}.json")
            paris_tr_df.to_csv(f"{paris_tr_file}.csv")
            print("----done running paris traceroutes")
        # find second-to-last hops
        sec_to_last_df = get_last_hops_from_paris_tr(f"{paris_tr_file}.json", asn)
        sec_to_last_df.to_csv(sec_to_last_file, index=None)
    

    # run roman hitchhiking
    date_str = datetime.now().strftime("%Y%m%d")
    modified_concurrent_output_dir = f"{output_dir}/{date_str}"
    os.makedirs(modified_concurrent_output_dir, exist_ok=True)
    modified_concurrent_file_name = f"{modified_concurrent_output_dir}/{asn}"
    if not os.path.exists(f"{modified_concurrent_file_name}_endpoint.csv") and \
        not os.path.exists(f"{modified_concurrent_file_name}_sec_last.csv"):
        print(f"file does not exist: {modified_concurrent_file_name}")

        print("----running modified concurrent pings")
        modified_concurrent_ttl_ping_by_grouping(
                sec_to_last_df, asn, 
                output_file=modified_concurrent_file_name, 
                wait_probe=probe_interval, 
                num_probes=num_probes,
                grouping=grouping, 
                sample_size=sample_size,
                slash=slash, 
                multiple_src_ips=multiple_src_ips,
                output_dir=output_dir,
        ) 
        print("----done running concurrent pings")

    else:
        print(f"file exists: {modified_concurrent_file_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Roman HitchHiking")

    parser.add_argument(
        "--probe-interval",
        type=int,
        required=True,
        help="Seconds between probes"
    )

    parser.add_argument(
        "--num-probes",
        type=int,
        required=True,
        help="Number of probes (0 = continuous)"
    )

    parser.add_argument(
        "--exposed-ips-file",
        type=str,
        default=None,
        help="Optional file of exposed IPs"
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default="roman-hh",
        help="Directory to store output files"
    )

    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    run_roman_hitchhiking(
        STARLINK_ASN,
        probe_interval=args.probe_interval,
        num_probes=args.num_probes,
        output_dir=args.output_dir,
        multiple_src_ips=True,
        grouping=None,
        sample_size=None,
        slash=None,
        exposed_ips_file=args.exposed_ips_file,
    )
