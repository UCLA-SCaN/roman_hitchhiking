import os
import pandas as pd

from .parse_geolocation import get_all_geoip, get_cleaned_censys

def get_endpoint_file(
        dir: str,
        sample_num: int,
):
    return f"{dir}/modified_concurrent_AS14593_{sample_num}_endpoint.csv"

def get_seclast_file(
        dir: str,
        sample_num: int,
):
    return f"{dir}/modified_concurrent_AS14593_{sample_num}_sec_last.csv"

def get_successful_data_points(
        df: pd.DataFrame, 
) -> pd.DataFrame:
    return df.dropna(subset=['rtt_endpoint', 'rtt_seclast'])

def get_outage_data_points(
        df: pd.DataFrame, 
) -> pd.DataFrame:
    return df[df['rtt_endpoint'].isna() & df['rtt_seclast'].notna()]

def get_viable_data_points(
        df: pd.DataFrame,
) -> pd.DataFrame:
    successful_df = get_successful_data_points(df)
    outage_df = get_outage_data_points(df)
    return pd.concat([successful_df, outage_df], ignore_index=True)

def get_presat_failure_data_points(
        df: pd.DataFrame, 
) -> pd.DataFrame:
    return df[df['rtt_endpoint'].notna() & df['rtt_seclast'].isna()]

def get_loss_data_points(
        df: pd.DataFrame, 
) -> pd.DataFrame:
    return df[df['rtt_endpoint'].isna() & df['rtt_seclast'].isna()]

def get_total_loss_data_points(
        df: pd.DataFrame, 
) -> pd.DataFrame:
    return df[(
        df['rtt_endpoint'].notna() & df['rtt_seclast'].isna()
        ) | (
        df['rtt_endpoint'].isna() & df['rtt_seclast'].isna()
    )]

def import_and_clean_df(
        seclast_file: str, endpoint_file: str, 
        censys_file: str, 
        output_dir: str,
        modified: bool = False,
        filter: bool = True,
        seclast_mapping: str = None,
        merge_censys: bool = False,
):
    """
    Imports data from data_collection/ and cleans it:
    - filters out invalid endpoints according to the original HitchHiking methodology.
    - maps the endpoint ips to their second-to-last ips and joins the data.
    - joins metadata (dns_name) from Censys data and Starlink GeoIP data.
    
    The 'ip_at_ttl' when conducting pre-satellite measurements very rarely changes.
    The average number of successful measurements for each pre-satellite hop is around 245.
    """

    if (
        os.path.exists(f"{output_dir}/outage.csv") 
        and os.path.exists(f"{output_dir}/latency.csv") 
    ):
        outages_df = pd.read_csv(f"{output_dir}/outage.csv")
        latency_df = pd.read_csv(f"{output_dir}/latency.csv")
        return outages_df, latency_df, None

    seclast_df = pd.read_csv(seclast_file, index_col=0)
    endpoint_df = pd.read_csv(endpoint_file, index_col=0)

    # only include pre-sat IPs with at least one viable data point
    seclast_filtered = seclast_df.dropna(subset='rtt')
    seclast_ips = list(seclast_filtered['ip_at_ttl'].unique())
    seclast_df = seclast_df[seclast_df['ip_at_ttl'].isin(seclast_ips)]

    # only include endpoint IPs with at least one viable data point
    endpoint_filtered = endpoint_df.dropna(subset='rtt')
    endpoint_ips = list(endpoint_filtered['dst'].unique())
    endpoint_df = endpoint_df[endpoint_df['dst'].isin(endpoint_ips)]

    # merge with endpoint ips with sec-to-last ip mapping
    if modified:
        seclast_endpoint_mapping = pd.read_csv(seclast_mapping)
        dst_representatives = list(seclast_df['dst'].unique())
        # find the sec_last_ips for the dst's chosen in the data
        mapping_dst_rep = (
            seclast_endpoint_mapping[
                seclast_endpoint_mapping['dst'].isin(dst_representatives)
            ][['dst', 'sec_last_ip']]
        )
        mapping_dst_rep = mapping_dst_rep.rename(columns={
            'dst': 'dst_rep',
        })

        seclast_dst_to_dst = seclast_endpoint_mapping[['dst', 'sec_last_ip']].merge(
            mapping_dst_rep,
            how='left',
            on='sec_last_ip',
        )

        df = (
            endpoint_df
            .merge(
                seclast_dst_to_dst[['dst', 'dst_rep']],
                how='left',
                on='dst',
            )
        )
        
        df = (
            df
            .merge(
                seclast_df[['seq', 'dst', 'ip_at_ttl', 'rtt']],
                how='left',
                left_on=['seq', 'dst_rep'],
                right_on=['seq', 'dst'],
                suffixes=['_endpoint', '_seclast'],
            )
        )

        df = df.rename(columns={
            'dst_endpoint': 'dst',
            })
        df['sec_last_ip'] = df['ip_at_ttl_seclast']

    else:
        df = (
            endpoint_df
            .merge(
                seclast_df[['seq', 'dst', 'ip_at_ttl', 'rtt']], 
                how='left', 
                left_on=['seq', 'dst'],
                right_on=['seq', 'dst'],
                suffixes=['_endpoint', '_seclast'],
            )
        )
        df['sec_last_ip'] = df['ip_at_ttl_seclast']

    df = df[[
        'seq', 'dst', 'sec_last_ip', 'ip_at_ttl_seclast', 
        'start_time', 'rtt_seclast', 'rtt_endpoint',
    ]]


    max_seq = df['seq'].max()
    loss_df = get_total_loss_data_points(df)
    loss_per_dst = (
        loss_df
        .groupby('dst')['seq']
        .nunique()
    )
    loss_per_dst_df = loss_per_dst.reset_index()
    loss_rate_per_dst = loss_per_dst / max_seq
    mean_loss = loss_rate_per_dst.mean()
    std_loss = loss_rate_per_dst.std()

    if filter:
        loss_per_dst_df['loss_rate'] = loss_per_dst_df['seq'] / max_seq

        failure_count_thresh = loss_per_dst_df[
            loss_per_dst_df['loss_rate'] > (mean_loss + 2 * std_loss)
        ]['dst'].unique()
        df = df[~df['dst'].isin(failure_count_thresh)]

    # Merge with Censys dns names
    if merge_censys: # Starlink-specific filtering
        censys_df = get_cleaned_censys(censys_file)
        censys_df = censys_df[['ip', 'dns_trunc']]
        censys_df = get_all_geoip(censys_df)
        censys_df.to_csv(f"{output_dir}/censys_cleaned.csv", index=False)
        df = df.merge(censys_df, how='inner', left_on='dst', right_on='ip')
        df = df.drop(columns='ip')
    df['sat_rtt'] = df['rtt_endpoint'] - df['rtt_seclast']
    df = df.drop_duplicates(subset=['dst', 'ip_at_ttl_seclast', 'seq'])

    # plot joined and filtered data
    df.to_csv(f"{output_dir}/latency.csv", index=False)
    outages_df = df[(df['rtt_seclast'].notna()) & (df['rtt_endpoint'].isna())]
    outages_df.to_csv(f"{output_dir}/outage.csv", index=False)

    outages_df = outages_df.copy()
    outages_df['seq'] = outages_df['seq'].astype(int)
    num_endpoints = df['dst'].nunique()
    return outages_df, df, num_endpoints
