import json
import ipaddress
import os
from typing import Iterable

import numpy as np
import pandas as pd

try:
    from ..config import DEFAULT_CONFIG_PATH, get_runtime_settings
    from .get_asn import get_asn_prefixes
except ImportError:
    from config import DEFAULT_CONFIG_PATH, get_runtime_settings
    from src.get_asn import get_asn_prefixes


LABEL_MAP = {
    "dropped": 0,
    "outage": 1,
    "asym": 2,
    "success": 3,
}


def _rtt_agg(values: pd.Series) -> float:
    non_na = values.dropna()
    if len(non_na) == 0:
        return np.nan
    return float(non_na.median())


def _iter_ping_rows(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.replace("\x00", "").strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                print(f"Skipping malformed JSON line in {path}: {line}")
                continue
            if obj.get("type") != "ping":
                continue

            dst = obj.get("dst")

            for response in obj.get("responses", []):
                yield {
                    "ip": response.get("from"),
                    "timestamp": response.get("tx", {}).get("sec"),
                    "rtt": response.get("rtt"),
                }

            for no_response in obj.get("no_responses", []):
                yield {
                    "ip": dst,
                    "timestamp": no_response.get("tx", {}).get("sec"),
                    "rtt": None,
                }


def parse_ping_file(path: str) -> pd.DataFrame:
    rows = list(_iter_ping_rows(path))
    if not rows:
        return pd.DataFrame(columns=["ip", "timestamp", "rtt"])

    return (
        pd.DataFrame(rows, columns=["ip", "timestamp", "rtt"])
        .sort_values(["ip", "timestamp"])
        .reset_index(drop=True)
    )


def aggregate_ping_file(path: str) -> pd.DataFrame:
    df = parse_ping_file(path)
    if df.empty:
        return pd.DataFrame(columns=["timestamp", "ip", "rtt"])

    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")
    return (
        df.groupby(["timestamp", "ip"], as_index=False)
        .agg({"rtt": _rtt_agg})
        .sort_values(["timestamp", "ip"])
        .reset_index(drop=True)
    )


def load_mapping_file(path: str) -> pd.DataFrame:
    mapping_df = pd.read_csv(path)
    columns = set(mapping_df.columns)

    if {"dst", "sec_last_ip"}.issubset(columns):
        normalized = mapping_df[["dst", "sec_last_ip"]].rename(
            columns={"dst": "ep_ip", "sec_last_ip": "sl_ip"}
        )
    elif {"ep_ip", "sl_ip"}.issubset(columns):
        normalized = mapping_df[["ep_ip", "sl_ip"]]
    else:
        raise ValueError(
            "mapping file "
            f"{path} is missing required columns. Expected either "
            "['dst', 'sec_last_ip'] or ['ep_ip', 'sl_ip']"
        )

    return (
        normalized
        .dropna(subset=["ep_ip", "sl_ip"])
        .drop_duplicates()
        .reset_index(drop=True)
    )


def _normalize_asn(asn: str | int | None) -> int | None:
    if asn is None:
        return None

    cleaned = str(asn).strip().upper()
    if not cleaned:
        return None
    if cleaned.startswith("AS"):
        cleaned = cleaned[2:]

    try:
        return int(cleaned)
    except ValueError:
        return None


def _resolve_allowed_asn(
    allowed_sec_last_asn: str | int | None,
    config_path: str | None,
) -> int | None:
    normalized = _normalize_asn(allowed_sec_last_asn)
    if normalized is not None:
        return normalized

    if config_path is None:
        return None

    return _normalize_asn(get_runtime_settings(config_path).get("asn"))


def _build_asn_fallback_df(
    sl_df: pd.DataFrame,
    allowed_sec_last_asn: int | None,
) -> pd.DataFrame:
    if sl_df.empty or allowed_sec_last_asn is None:
        return pd.DataFrame(columns=["timestamp", "sl_rtt"])

    prefixes = get_asn_prefixes(allowed_sec_last_asn)
    if not prefixes:
        return pd.DataFrame(columns=["timestamp", "sl_rtt"])

    def _ip_in_allowed_asn(ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(ip_obj in prefix for prefix in prefixes)

    fallback_df = sl_df[sl_df["ip"].map(_ip_in_allowed_asn)].copy()
    if fallback_df.empty:
        return pd.DataFrame(columns=["timestamp", "sl_rtt"])

    return (
        fallback_df.groupby("timestamp", as_index=False)
        .agg({"rtt": _rtt_agg})
        .rename(columns={"rtt": "sl_rtt"})
        .sort_values("timestamp")
        .reset_index(drop=True)
    )


def merge_ttl_ping_outputs(
    endpoint_path: str,
    sec_last_path: str,
    mapping_path: str,
    allowed_sec_last_asn: str | int | None = None,
    config_path: str | None = None,
) -> pd.DataFrame:
    ep_df = aggregate_ping_file(endpoint_path)
    sl_df = aggregate_ping_file(sec_last_path)
    mapping_df = load_mapping_file(mapping_path)
    allowed_asn = _resolve_allowed_asn(allowed_sec_last_asn, config_path)
    sl_asn_fallback_df = _build_asn_fallback_df(sl_df, allowed_asn)

    merged_df = (
        ep_df.rename(columns={"ip": "ep_ip", "rtt": "ep_rtt"})
        .merge(mapping_df, on="ep_ip", how="left")
        .merge(
            sl_df.rename(columns={"ip": "sl_ip", "rtt": "sl_rtt"}),
            on=["timestamp", "sl_ip"],
            how="left",
        )
        .merge(
            sl_asn_fallback_df.rename(columns={"sl_rtt": "sl_rtt_asn_fallback"}),
            on="timestamp",
            how="left",
        )
        .assign(
            sl_rtt=lambda df: df["sl_rtt"].combine_first(df["sl_rtt_asn_fallback"])
        )
        [["timestamp", "ep_ip", "sl_ip", "ep_rtt", "sl_rtt"]]
        .sort_values(["timestamp", "ep_ip"])
        .reset_index(drop=True)
    )

    conditions = [
        merged_df["ep_rtt"].isna() & merged_df["sl_rtt"].isna(),
        merged_df["ep_rtt"].notna() & merged_df["sl_rtt"].notna(),
        merged_df["ep_rtt"].notna() & merged_df["sl_rtt"].isna(),
        merged_df["ep_rtt"].isna() & merged_df["sl_rtt"].notna(),
    ]
    choices = ["dropped", "success", "asym", "outage"]
    merged_df["label"] = np.select(conditions, choices, default="unknown")
    merged_df["label_num"] = merged_df["label"].map(LABEL_MAP)

    return merged_df


def clean_merged_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df.copy()

    cleaned = df.copy()

    sl_ips_nan = (
        cleaned.groupby("sl_ip")["sl_rtt"]
        .apply(lambda x: x.isna().all())
        .reset_index()
    )
    unresponsive_sl_ips = sl_ips_nan[sl_ips_nan["sl_rtt"]]["sl_ip"].dropna().tolist()
    if unresponsive_sl_ips:
        cleaned = cleaned[~cleaned["sl_ip"].isin(unresponsive_sl_ips)].copy()
        if cleaned.empty:
            return cleaned.reset_index(drop=True)

    no_success_ips = (
        cleaned.groupby("ep_ip")["label"]
        .apply(lambda x: (x != "success").all())
        .reset_index()
    )
    no_success_ips = no_success_ips[no_success_ips["label"]]["ep_ip"].dropna().tolist()
    if no_success_ips:
        cleaned = cleaned[~cleaned["ep_ip"].isin(no_success_ips)].copy()

    return cleaned.reset_index(drop=True)


def get_processed_output_path(endpoint_path: str) -> str:
    if endpoint_path.endswith("_endpoint.json"):
        prefix = endpoint_path[: -len("_endpoint.json")]
    elif endpoint_path.endswith("endpoint.json"):
        prefix = endpoint_path[: -len("endpoint.json")]
    else:
        prefix = os.path.splitext(endpoint_path)[0]

    if prefix.endswith("_"):
        prefix = prefix[:-1]

    return f"{prefix}_merged_filtered.csv"


def process_ttl_ping_bucket(
    endpoint_path: str,
    sec_last_path: str,
    mapping_path: str,
    filtered_output_path: str | None = None,
    allowed_sec_last_asn: str | int | None = None,
    config_path: str = DEFAULT_CONFIG_PATH,
) -> str:
    if filtered_output_path is None:
        filtered_output_path = get_processed_output_path(endpoint_path)

    merged_df = merge_ttl_ping_outputs(
        endpoint_path,
        sec_last_path,
        mapping_path,
        allowed_sec_last_asn=allowed_sec_last_asn,
        config_path=config_path,
    )
    cleaned_df = clean_merged_dataframe(merged_df)

    cleaned_df.to_csv(filtered_output_path, index=False)

    return filtered_output_path
