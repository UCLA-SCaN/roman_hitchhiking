import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import pandas as pd
import os

from .src.config import FIG_OUTPUT_DIR, PATH
from .src.import_data import import_and_clean_df

def plot_detected_outages_by_methodology(
        count_df: list,
        labels: list,
        fig_output_dir: str,
        outage_len: int = 5,
):
    def group_consecutive_graph(seq_list):
        grouped = []
        current_group = []
        for i, val in enumerate(sorted(seq_list)):
            if not current_group or val == current_group[-1] + 1:
                current_group.append(val)
            else:
                grouped.append(current_group)
                current_group = [val]
        if current_group:
            grouped.append(current_group)
        return grouped

    fig, axs = plt.subplots(2, 1, figsize=(10, 3), sharex=True, constrained_layout=True)
    fig, axs = plt.subplots(2, 1, figsize=(10, 3), sharex=True, constrained_layout=True)

    # Line plot
    axs[0].plot(count_df['seq'], count_df['count'], marker='o', markersize=4)
    axs[0].set_ylabel('Number of \nMeasurements')
    axs[0].set_xlabel('Sequence Number')
    axs[0].tick_params(labelbottom=True)
    axs[0].grid(True, linestyle='--', alpha=0.5)
    axs[0].yaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    # Highlight outage regions for last df in outage_df
    last_df_seqs = count_df[count_df['is_in_last_df'] == True]['seq']
    last_df_groups = group_consecutive_graph(last_df_seqs)
    for group in last_df_groups:
        if len(group) >= outage_len:
            axs[0].axvspan(
                group[0], group[-1], 
                color='red', alpha=0.15, 
                label=f'Last DF (≥{outage_len})',
            )

    cmap = plt.get_cmap('tab10')
    colors = [cmap(i) for i in range(len(outage_dfs))]

    # Scatter plot
    for idx, (df, label, color) in enumerate(zip(outage_dfs, labels, colors)):
        filtered = df[df['dst'] == target_dst]
        if not filtered.empty:
            seqs = filtered['seq']
            axs[1].scatter(
                seqs, [idx] * len(seqs),
                label=label,
                facecolors='none',
                edgecolors=color,
                linewidths=1,
                s=10,
            )

    axs[1].set_yticks(range(len(labels)))
    axs[1].set_yticklabels(labels)
    axs[1].set_xlabel('Sequence Number')
    axs[1].grid(True, linestyle='--', alpha=0.5)

    fig.savefig(f"{fig_output_dir}/naive_roman_rl_outage_{target_dst}.png")
    plt.close(fig)


DATA = f"{PATH}/data/naive_roman_rl"
censys_file = f'{PATH}/data/censys_exposed_services_AS14593.csv'


NAIVE_OUTPUT_PATH = f"{DATA}/naive"
ROMAN_OUTPUT_PATH = f"{DATA}/roman"
RL_OUTPUT_PATH = f"{DATA}/roman_large"

os.makedirs(NAIVE_OUTPUT_PATH, exist_ok=True)
os.makedirs(ROMAN_OUTPUT_PATH, exist_ok=True)
os.makedirs(RL_OUTPUT_PATH, exist_ok=True)

NAIVE_SECLAST_FILE = f"{DATA}/modified_concurrent_AS14593_4_naive_sec_last.csv"
NAIVE_ENDPOINT_FILE = f"{DATA}/modified_concurrent_AS14593_4_naive_endpoint.csv"

ROMAN_SECLAST_FILE = f"{DATA}/modified_concurrent_AS14593_4_roman_sec_last.csv"
ROMAN_ENDPOINT_FILE = f"{DATA}/modified_concurrent_AS14593_4_roman_endpoint.csv"
ROMAN_MAPPING_FILE = f"{DATA}/modified_concurrent_AS14593_4_sec_last_actual_vs_expected_roman.csv"

RL_SECLAST_FILE = f"{DATA}/modified_concurrent_AS14593_4_rl_sec_last.csv"
RL_ENDPOINT_FILE = f"{DATA}/modified_concurrent_AS14593_4_rl_endpoint.csv"
RL_MAPPING_FILE = f"{DATA}/modified_concurrent_AS14593_4_sec_last_actual_vs_expected_rl.csv"

data_files = [
    {
        'seclast_file': NAIVE_SECLAST_FILE,
        'endpoint_file': NAIVE_ENDPOINT_FILE,
        'mapping_file': None,
        'output_dir': NAIVE_OUTPUT_PATH,
        'modified': False,
        'label': r"Naive",
    },
    {
        'seclast_file': ROMAN_SECLAST_FILE,
        'endpoint_file': ROMAN_ENDPOINT_FILE,
        'mapping_file': ROMAN_MAPPING_FILE,
        'output_dir': ROMAN_OUTPUT_PATH,
        'modified': True,
        'label': r"Roman",
    },
    {
        'seclast_file': RL_SECLAST_FILE,
        'endpoint_file': RL_ENDPOINT_FILE,
        'mapping_file': RL_MAPPING_FILE,
        'output_dir': RL_OUTPUT_PATH,
        'modified': True,
        'label': r"Roman Large",
    },
]

target_dst = '129.222.5.64'
outage_dfs = []

for data_f in data_files:
    if (os.path.exists("{data_f['output_dir']}/naive_roman_rl_outage_{target_dst}.csv")):
        outage_df = pd.read_csv(f"{data_f['output_dir']}/naive_roman_rl_outage_{target_dst}.csv")
        outage_dfs.append(outage_df)
    else:
        outage_df, latency_df, _ = import_and_clean_df(
            seclast_file=data_f['seclast_file'],
            endpoint_file=data_f['endpoint_file'],
            censys_file=censys_file,
            output_dir=data_f['output_dir'],
            modified=data_f['modified'],
            filter=True,
            seclast_mapping=data_f['mapping_file'],
            merge_censys=True
        )
        outage_df = outage_df.sort_values(['dst', 'seq'])
        outage_df = outage_df[outage_df['dst'] == target_dst]
        outage_df.to_csv(
            f"{data_f['output_dir']}/naive_roman_rl_outage_{target_dst}.csv", 
            index=False,
        )
        outage_dfs.append(outage_df)



seqs_per_df = [set(df['seq']) for df in outage_dfs]
all_seqs = sorted(set().union(*seqs_per_df))

# Get the seqs present in the LAST dataframe (Roman Large)
last_df_seqs = set(outage_dfs[-1][outage_dfs[-1]['dst'] == target_dst]['seq'])

data = []
for seq in all_seqs:
    count = sum(seq in df_seqs for df_seqs in seqs_per_df)
    in_last_df = seq in last_df_seqs
    data.append((seq, count, in_last_df))

count_df = pd.DataFrame(data, columns=['seq', 'count', 'is_in_last_df']).sort_values('seq')
count_df['count'] = count_df['count'].astype(int)

labels = [r"Naive", r"Roman", r"Roman Large"]
plot_detected_outages_by_methodology(
    count_df, labels, FIG_OUTPUT_DIR
)


