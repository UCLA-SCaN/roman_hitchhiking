import os
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from .src.config import FIG_OUTPUT_DIR, PATH

def packets_received_box_plot(
        probes_to_packet: pd.DataFrame, 
        fig_output_dir: str,
):
    # 60 probes over 60 seconds, this may be different depending on your data collection
    max_seq = 59 

    probes_to_packet_seq = probes_to_packet
    probes_to_packet_seq['seq_loss_perc'] = probes_to_packet['seq'].apply(
        lambda x: (max_seq - x)/max_seq * 100
    )

    probes_to_packet = probes_to_packet.sort_values(by='seq', ascending=False)

    probes_to_packet = (
        probes_to_packet
        .groupby('ip_at_ttl')
        .agg({
            'dst': 'nunique',
        })
        .reset_index()
    )
    probes_to_packet = probes_to_packet.sort_values(by='dst', ascending=False)
    #--------- Plot # of probes to # of packets received
    # Bin the 'dst' values
    max_dst_per_sec_last = probes_to_packet['dst'].max()
    if max_dst_per_sec_last < 100:
        probes_to_packet['dst_bin'] = probes_to_packet['dst']
    else:
        fixed_bins = list(range(0, 101, 10))  # [0, 10, ..., 100]
        bins = fixed_bins + [max_dst_per_sec_last]  # Avoid duplicate 100

        # Create labels
        labels = []
        for i in range(len(bins) - 1):
            start = bins[i] + 1 if i > 0 else bins[i]
            end = bins[i + 1]
            if i == len(bins) - 2:
                labels.append(f"{start}+")
            else:
                labels.append(f"{start}-{end}")

        # Apply binning
        probes_to_packet['dst_bin'] = pd.cut(
            probes_to_packet['dst'],
            bins=bins,
            labels=labels,
            right=True,
            include_lowest=True
        )

    probes_to_packet_seq = (
        probes_to_packet_seq
        .merge(
            probes_to_packet[['ip_at_ttl', 'dst_bin']], 
            how='left', 
            on=['ip_at_ttl'],
        )
    )

    # Plot % of Packets Lost
    plt.figure(figsize=(5, 3))
    ax = sns.boxplot(data=probes_to_packet_seq, x='dst_bin', y='seq_loss_perc')
    plt.xlabel('# of Customers that Share a Pre-Satellite Hop Router')
    plt.xticks(rotation=45)
    plt.ylabel(f'Average Packet Loss (%)')
    plt.tight_layout()
    plt.show()
    fig_name = f'{fig_output_dir}/naive_packet_loss_per_seclast.png'
    print(f'saving to {fig_name}')
    plt.savefig(fig_name)



naive_dir = f"{PATH}/data/naive"
naive_seclast_file = f"{naive_dir}/concurrent_AS14593_sec_last.csv"

if os.path.exists(f"{naive_dir}/probes_to_pkt_rate.csv"):
    probes_to_packet = pd.read_csv(f"{naive_dir}/probes_to_pkt_rate.csv")
else:
    naive_df = pd.read_csv(naive_seclast_file)
    naive_df = naive_df.dropna(subset=['rtt'])
    print(naive_df)

    probes_to_packet = (
        naive_df
        .groupby(['ip_at_ttl', 'dst'])['seq']
        .nunique()
        .reset_index()
    )
    probes_to_packet.to_csv(f"{naive_dir}/probes_to_pkt_rate.csv", index=False)

# plot packets received for concurrent measurements
packets_received_box_plot(probes_to_packet, FIG_OUTPUT_DIR)
