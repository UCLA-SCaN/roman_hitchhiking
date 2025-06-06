import os
import pandas as pd
from src.constants import STARLINK_ASN, HURRICANE_ELECTRIC_ASN
from data_collection.services_from_censys import get_censys_exposed_services
from data_collection.run_scamper import Grouping, modified_concurrent_ttl_ping_by_grouping, run_paris_trs
from data_collection.parse_scamper import get_last_hops_from_paris_tr

"""
Runs Roman HitchHiking
"""

OUTPUT_DIR = "roman-hh"
os.makedirs(OUTPUT_DIR)

def run_roman_hitchhiking(
        asn: str, 
        probe_interval: int, 
        num_probes: int,  
        multiple_src_ips: bool = True, 
        grouping: Grouping = None, 
        sample_size: int = None, 
        slash: int = None,
):
    """
    :param asn: the autonomous system number formatted as "AS####"
    """
    as_num = asn[2:]

    # get exposed services
    censys_exposed_services_file = f"{OUTPUT_DIR}/censys_exposed_services_{asn}.csv"
    censys_exposed_ips_file = f"{OUTPUT_DIR}/censys_exposed_ips_{asn}.txt"
    if os.path.exists(censys_exposed_services_file):
        print(f"file exists: {censys_exposed_services_file}")
        censys_df = pd.read_csv(censys_exposed_services_file)
    else:
        print(f"file doesn't exist: {censys_exposed_services_file}")
        print("----querying Censys for exposed services")
        censys_df = get_censys_exposed_services(int(as_num))
        censys_df.to_csv(censys_exposed_services_file)
        censys_df[['ip']].to_csv(censys_exposed_ips_file, header=None, index=None)
        print("----done querying Censys for exposed services")

    # paris traceroute all exposed services
    paris_tr_file = f"{OUTPUT_DIR}/paris_tr_{asn}"
    sec_to_last_file = f"{OUTPUT_DIR}/sec_last_{asn}.csv"
    if os.path.exists(f"{sec_to_last_file}"):
        print(f"file exists: {paris_tr_file}.csv")
        # find second-to-last hops
        sec_to_last_df = pd.read_csv(sec_to_last_file)
    else:
        print(f"file doesn't exists: {paris_tr_file}.csv")
        print("----running paris traceroutes")
        paris_tr_df = run_paris_trs(censys_exposed_ips_file, f"{paris_tr_file}.json")
        paris_tr_df.to_csv(f"{paris_tr_file}.csv")
        print("----done running paris traceroutes")
        # find second-to-last hops
        sec_to_last_df = get_last_hops_from_paris_tr(f"{paris_tr_file}.json", asn)
        sec_to_last_df.to_csv(sec_to_last_file, index=None)
    


    # run roman hitchhiking
    modified_concurrent_output_dir = f"{OUTPUT_DIR}/modified_all_may29"
    os.makedirs(modified_concurrent_output_dir, exist_ok=True)
    modified_concurrent_file_name = f"{modified_concurrent_output_dir}/modified_concurrent_{asn}"
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
        ) 
        print("----done running concurrent pings")

    else:
        print(f"file exists: {modified_concurrent_file_name}")


run_roman_hitchhiking(STARLINK_ASN)
