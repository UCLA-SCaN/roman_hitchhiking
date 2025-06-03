import os
import geopandas as gpd
import matplotlib.pyplot as plt
import pandas as pd

from .src.import_data import get_endpoint_file, get_seclast_file, import_and_clean_df
from .src.config import FIG_OUTPUT_DIR, PATH
from .src.outage_analysis import get_consecutive_df

# Merge grouped_counts with countries GeoDataFrame on country name (adjust as needed)
geopandas_data = "" # FIXME

"""
[
    { 'start': int, 'end': int }, 
    { 'start': int, 'end': int }, 
]
"""
def investigate_spike(
        outage_df: pd.DataFrame,
        location_df: pd.DataFrame,
        spike_intervals, 
        label: str, 
        fig_output_dir: str,
):
    outages_at_spike = pd.DataFrame()
    for spike_interval in spike_intervals:
        start = spike_interval['start']
        end = spike_interval['end']
        outages_at_curr_spike = outage_df[(outage_df['len'] >= start) & (outage_df['len'] < end)]
        outages_at_spike = pd.concat([outages_at_spike, outages_at_curr_spike], ignore_index=True)

    spike_df = outages_at_spike.merge(
        location_df
        .groupby('dst', as_index=False).first(),
        how='left',
        on='dst',
    )
    spike_explode_df = spike_df.explode('seqs')

    country_counts = (
        spike_explode_df
        .groupby('country')['dst']
        .nunique()
        .reset_index()
        .rename(columns={'dst': 'unique_dst_count'})
    )
    countries = gpd.read_file(f'{geopandas_data}/ne_110m_admin_0_countries.shp')
    countries = countries.merge(country_counts, left_on='ISO_A2', right_on='country', how='left')

    fig, ax = plt.subplots(figsize=(8, 4))

    # Plot countries without data as grey
    countries.plot(
        ax=ax,
        color='lightgrey',
        edgecolor='white'
    )
    # Plot countries with data colored by unique_dst_count
    countries_with_data = countries.dropna(subset=['unique_dst_count'])
    countries_with_data.plot(
        ax=ax,
        column='unique_dst_count',
        cmap='Reds',
        legend=True,
        edgecolor='black',
        legend_kwds={'label': "Number of Customers Affected", 'shrink': 0.6}
    )

    # Style
    ax.axis('off')
    plt.tight_layout()
    plt.savefig(f"{fig_output_dir}/spike_country_choropleth_{label}_{start}_{end}.png")
    plt.show()



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

    if (os.path.exists(f"{OUTPUT_DIR}/consecutive_outages.csv") 
        and os.path.exists(f"{OUTPUT_DIR}/dst_locations.csv")
    ):
        consec_df = pd.read_csv(f"{OUTPUT_DIR}/consecutive_outages.csv")
        location_df = pd.read_csv(f"{OUTPUT_DIR}/dst_locations.csv")

    else:
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

        location_df = latency_df[[
            'dst', 'sec_last_ip', 'dns_trunc', 'subnet', 'country', 'region',
        ]].drop_duplicates().dropna(subset=['dst', 'country'])

        location_df.to_csv(f"{OUTPUT_DIR}/dst_locations.csv", index=False)

    dfs_and_labels.append({
        'df': consec_df,
        'location_df': location_df,
        'label': d['label'],
        'output': FIG_OUTPUT_DIR,
    })

may_27_data = dfs_and_labels[0]
may_29_data = dfs_and_labels[2]
investigate_spike(
    may_27_data['df'], 
    may_27_data['location_df'],
    [ { 'start': 70, 'end': 75+1 } ],
    may_27_data['label'], 
    may_27_data['output'], 
) 

investigate_spike(
    may_29_data['df'], 
    may_29_data['location_df'],
    [ 
         { 'start': 50, 'end': 55+1 },
         { 'start': 70, 'end': 75+1 },
    ],
    may_29_data['label'], 
    may_29_data['output'], 
) 
