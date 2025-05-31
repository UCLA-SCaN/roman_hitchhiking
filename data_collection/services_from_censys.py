import pandas as pd
from google.cloud import bigquery
from typing import Union, List

CENSYS_UNIVERSAL_DATASET_BQ_TABLE = 'censys-io.universal_internet_dataset_v2.base'

def get_censys_exposed_services(asn: Union[int, List[int]], ipv: int = None, ) -> pd.DataFrame:
    """
    Queries Censys for exposed services and returns the result as a dataframe.
    Assumes access to the Censys Universal Datasest in BigQuery

    :param asn: the autonomous system number to query
    :param ipv: (optional) specify 4 or 6 to filter for IP version
    :param bq: (optional) the BigQuery table to pull data from
    :return: dataframe of exposed services information
    """

    if isinstance(asn, list):
        asn_list = [f"autonomous_system.asn={n}" for n in asn]
        asn_bq = " OR ".join(asn_list)
    else:
        asn_bq = f"autonomous_system.asn={asn}"

    try:
        client = bigquery.Client()
        ip_col = 'host_identifier.ipv6' if ipv == 6 else 'host_identifier.ipv4'
        QUERY = (
            'SELECT DISTINCT '
            '    {ip_col} as ip, '
            '    CURRENT_DATE() as date, '
            '    autonomous_system.asn as asn, '
            '    dns.reverse_dns.names as dns_name, '
            '    ports_list as port, '
            '    ARRAY( '
            '     SELECT '
            '      CASE '
            '        WHEN LOWER(service.tls.certificates.leaf_data.subject_dn) LIKE "%peplink%" '
            '        THEN TRUE '
            '        ELSE FALSE '
            '      END '
            '     FROM UNNEST(services) AS service '
            '   ) AS pep_link '
            'FROM `{table}` '
            'WHERE '
            '    ({asn_bq}) AND '
            '    TIMESTAMP_TRUNC(snapshot_date, DAY) = TIMESTAMP(DATE_SUB(CURRENT_DATE, INTERVAL 2 DAY)) '  # we can only guarantee that censys's data from yesterday is available , reverse dns names take another day to populate in dataset
            '    AND {ip_col} IS NOT NULL '
        ).format(ip_col=ip_col, asn_bq=asn_bq, table=CENSYS_UNIVERSAL_DATASET_BQ_TABLE)
        query_job = client.query(QUERY)  # API request
        query_job.result()  # Waits for query to finish
        bq_df = query_job.to_dataframe()

        return bq_df

    except Exception as e:
        print(f"An error occurred: {e}")
        return None
