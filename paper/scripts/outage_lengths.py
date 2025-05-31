import matplotlib.pyplot as plt
import os
import pandas as pd
import seaborn as sns

from .src.config import FIG_OUTPUT_DIR, PATH
from .src.outage_analysis import get_consecutive_df
from .src.import_data import get_endpoint_file, get_seclast_file, import_and_clean_df

def plot_outage_length_cdf(
        outages_and_labels: list, 
        output_dir: str, 
        min_outage_len: int = 5,
):
    """
    For each entry in `outages_and_labels`, plot the CDF of outages by
    outage length.

    :param outages_and_labels: list of objects formatted lik
        {
            'df': pd.Dataframe,
            'label': str, 
        }
    :param output_dir: directory to save the figure
    :param min_outage_len: (optional), minimum outage length to filter for
                            default is 5 consecutive sequence numbers
    """
    plt.figure(figsize=(5, 3))

    #--- CDF
    colors = sns.color_palette("tab10", len(outages_and_labels))
    for i, info in enumerate(outages_and_labels):
        
        color = colors[i]
        sorted_lengths = info['df']['len'].sort_values()

        # Calculate cumulative distribution
        cdf = sorted_lengths.rank(method='first') / len(sorted_lengths)
        plt.plot(
            sorted_lengths, cdf, 
            drawstyle='steps-post', 
            label=f"{info['label']}",
            color=color,
        )

    plt.xlabel('Outage Length (seconds)')
    plt.ylabel('Cumulative Fraction\nof Outages')
    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.25), ncol=3)
    plt.ylim(0, 1)
    plt.xlim(5, None)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(f"{output_dir}/outage_length_cdf_plot.png")


censys_file = f'{PATH}/data/censys_exposed_services_AS14593.csv'
data_list = [
    {
        'data_dir': f'{PATH}/data/roman-hh-may27',
        'sample_size': 300,
        'label': 'May 27',
    },
    {
        'data_dir': f'{PATH}/data/roman-hh-may28',
        'sample_size': 300,
        'label': 'May 28',
    },
    {
        'data_dir': f'{PATH}/data/roman-hh-may29',
        'sample_size': 300,
        'label': 'May 29',
    },
]

min_outage_len = 5
dfs_and_labels = []
for d in data_list:
    OUTPUT_DIR = d['data_dir']
    INPUT_DIR = d['data_dir']
    sample_size = d['sample_size']

    if (os.path.exists(f"{OUTPUT_DIR}/consecutive_outages.csv")):
        consec_df = pd.read_csv(f"{OUTPUT_DIR}/consecutive_outages.csv")

    else:
        # seclast_endpoint_mapping = pd.read_csv(f"{dir}/modified_concurrent_AS14593_{sample_size}_sec_last_actual_vs_expected.csv")
        endpoint_file = get_endpoint_file(INPUT_DIR, sample_size)
        seclast_file = get_seclast_file(INPUT_DIR, sample_size)
        outages_df, latency_df, _ = import_and_clean_df(
                seclast_file, 
                endpoint_file,
                censys_file, 
                OUTPUT_DIR,
                modified=True,
                seclast_mapping = f'{INPUT_DIR}/modified_concurrent_AS14593_{sample_size}_sec_last_actual_vs_expected.csv',
                merge_censys = True,
        )
        consec_df = get_consecutive_df(outages_df)
        consec_df = consec_df[consec_df['len'] > min_outage_len]
        consec_df.to_csv(f"{OUTPUT_DIR}/consecutive_outages.csv", index=False)

    dfs_and_labels.append({
        'df': consec_df,
        'label': d['label'],
    })


plot_outage_length_cdf(dfs_and_labels, FIG_OUTPUT_DIR)
