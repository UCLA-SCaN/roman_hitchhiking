import matplotlib.pyplot as plt
import os
import pandas as pd
import re

from .src.config import FIG_OUTPUT_DIR, PATH
from .src.import_data import get_total_loss_data_points, import_and_clean_df

CENSYS_FILE = f'{PATH}/data/censys_exposed_services_AS14593.csv'

def get_packet_loss_rate(
        dir: str,
        output_dir: str,
        modified: bool = False,
) -> pd.DataFrame:
    """
    Plots valid measurement rates per sample size, invalid measurement rates per sample size.
    Plots data type splits (successful, outage, loss, pre-sat failure) per sample size
    """
    if (os.path.exists(f"{output_dir}/packet_loss_by_sample_size.csv")):
        packet_loss_df = pd.read_csv(f"{output_dir}/packet_loss_by_sample_size.csv")
        return packet_loss_df

    failure_frac_data = []

    pattern = re.compile(r"^modified_concurrent_AS14593_(\d+)_endpoint\.csv$")
    matching_files = []
    for filename in os.listdir(dir):
        match = pattern.match(filename)
        if match:
            sample_size = int(match.group(1))  # Extract the integer if needed
            matching_files.append((filename, sample_size))

    matching_files.sort(key=lambda x: x[1])

    for endpoint_file_name, sample_size in matching_files:
        tmp_endpoint_file = f"{dir}/modified_concurrent_AS14593_{sample_size}_endpoint.csv"
        tmp_seclast_file = f"{dir}/modified_concurrent_AS14593_{sample_size}_sec_last.csv"
        tmp_seclast_endpoint_mapping_file = f"{dir}/modified_concurrent_AS14593_{sample_size}_sec_last_actual_vs_expected.csv"
        tmp_output_dir = f'{output_dir}/sample_{sample_size}' 
        os.makedirs(tmp_output_dir, exist_ok=True)
        _, tmp_df, _ = import_and_clean_df(
            seclast_file=tmp_seclast_file,
            endpoint_file=tmp_endpoint_file,
            censys_file=CENSYS_FILE,
            output_dir=tmp_output_dir,
            modified=modified,
            filter=False,
            seclast_mapping=tmp_seclast_endpoint_mapping_file,
            merge_censys=True,
        )

        total_measurements = len(tmp_df)
        total_loss_df = get_total_loss_data_points(tmp_df)

        # fraction of all measurements that fail
        fail_frac = len(total_loss_df) / total_measurements
        failure_frac_data.append({
            'sample_size': sample_size,
            'num_endpoints': tmp_df['dst'].nunique(),
            'frac':  fail_frac,
        })

    packet_loss_df = pd.DataFrame(failure_frac_data)
    packet_loss_df = packet_loss_df.sort_values(by='num_endpoints')
    packet_loss_df.to_csv(f"{output_dir}/packet_loss_by_sample_size.csv", index=False)

    return packet_loss_df

def plot_measurement_success_of_different_sampling_methods(
        failure_dfs: list[pd.DataFrame],
        output_dir: str,
        fig_name: str,
        labels: list[str] = None,
):
    """
    Plot line graph of "valid" measurements different sample methods and sizes.
    Plot line graph of "invalid" measurements.
    :param success_dfs: a list of dataframes with columns: 'num_endpoints', 'frac'
    :param failure_dfs: a list of dataframes with columns: 'num_endpoints', 'frac'
                        must have the same length as success_dfs
    """
    # --- how does the subnet sampling vs. sec-last sampling affect failure rates?
    cmap = plt.get_cmap('tab10')
    colors = [cmap(i) for i in range(len(failure_dfs))]

    plt.figure(figsize=(5, 3))
    for ind, df in enumerate(failure_dfs):
        df = df.sort_values(by=['sample_size'])
        plt.plot(
            df['sample_size'], 
            df['frac'] * 100, 
            label=labels[ind] if labels else None, 
            color=colors[ind], 
            marker='o',
            markersize=4,
        )
    plt.xlabel('Number of Customers Sampled from a Partition Group')
    plt.ylabel('Packet Loss (%)')
    plt.legend(
        loc='upper center',
        bbox_to_anchor=(0.5, -0.25),
        ncol=2,  # Adjust number of columns if needed
        fontsize='small',
    )
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f'{output_dir}/{fig_name}.png')

    
SUBNET_DIR = f"{PATH}/data/naive_partition/subnet"
subnet_failure_df = get_packet_loss_rate(
    SUBNET_DIR,
    SUBNET_DIR,
)

# --- SEC-LAST sample size
SECLAST_DIR = f"{PATH}/data/naive_partition/seclast"
seclast_failure_df = get_packet_loss_rate(
    SECLAST_DIR,
    SECLAST_DIR,
)

plot_measurement_success_of_different_sampling_methods(
    [subnet_failure_df],
    FIG_OUTPUT_DIR,
    "packet_loss_by_sample_size",
    ['subnet'],
)
# --- SUBNET vs. SEC-LAST
# --- how does the subnet sampling vs. sec-last sampling affect failure rates?
plot_measurement_success_of_different_sampling_methods(
    [subnet_failure_df, seclast_failure_df],
    FIG_OUTPUT_DIR,
    "packet_loss_by_sample_size_subnet_vs_seclast",
    ['subnet', 'pre-satellite hop'],
)


MULTI_DIR = f"{DATA_PATH}/concurrent_multi_src"
SINGLE_DIR = f"{DATA_PATH}/concurrent_single_src"
ROMAN_MULTI_DIR = f"{DATA_PATH}/modified_concurrent_multi_src"
ROMAN_SINGLE_DIR = f"{DATA_PATH}/modified_concurrent_single_src"

SINGLE_OUTPUT_DIR = f"{PATH}/data/measurement_config_comp/naive_single"
MULTI_OUTPUT_DIR = f"{PATH}/data/measurement_config_comp/naive_multiple"
ROMAN_SINGLE_OUTPUT_DIR = f"{PATH}/data/measurement_config_comp/roman_single"
ROMAN_MULTI_OUTPUT_DIR = f"{PATH}/data/measurement_config_comp/roman_multiple"
# --- measurement configuration comparison
single_failure_df = get_packet_loss_rate(
    SINGLE_DIR,
    SINGLE_OUTPUT_DIR,
    modified=False,
)

multi_failure_df = get_packet_loss_rate(
    MULTI_DIR,
    MULTI_OUTPUT_DIR,
    modified=False,
)

roman_single_failure_df = get_packet_loss_rate(
    ROMAN_SINGLE_DIR,
    ROMAN_SINGLE_OUTPUT_DIR,
    modified=True,
)

roman_multi_failure_df = get_packet_loss_rate(
    ROMAN_MULTI_DIR,
    ROMAN_MULTI_OUTPUT_DIR,
    modified=True,
)

plot_measurement_success_of_different_sampling_methods(
    [single_failure_df, multi_failure_df, roman_single_failure_df, roman_multi_failure_df],
    FIG_OUTPUT_DIR,
    "packet_loss_by_measurement_config.png"
    ['1 Source IP (Naive)', '8 Source IPs (Naive)', '1 Source IP (Roman)', '8 Source IPs (Roman)'],
)