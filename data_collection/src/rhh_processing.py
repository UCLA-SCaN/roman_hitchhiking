import json
import ipaddress
import os
from collections import defaultdict
from typing import Iterable
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd
import polars as pl
import orjson
import tempfile

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


def _median_rtt(values: Iterable[float | None]) -> float:
    non_na = [value for value in values if value is not None and not pd.isna(value)]
    if not non_na:
        return np.nan
    return float(np.median(non_na))


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
    rows = [
        (row["ip"], row["timestamp"], row["rtt"])
        for row in _iter_ping_rows(path)
    ]
    if not rows:
        return pd.DataFrame(columns=["ip", "timestamp", "rtt"])

    return (
        pd.DataFrame.from_records(rows, columns=["ip", "timestamp", "rtt"])
        .sort_values(["ip", "timestamp"])
        .reset_index(drop=True)
    )


def aggregate_ping_file_polars(path: str) -> pl.DataFrame:
    timestamps = []
    ips = []
    rtts = []

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.replace("\x00", "").strip()
            if not line:
                continue

            try:
                obj = orjson.loads(line)
            except Exception:
                continue

            if obj.get("type") != "ping":
                continue

            dst = obj.get("dst")

            for r in obj.get("responses", []):
                tx = r.get("tx")
                if tx:
                    timestamps.append(tx.get("sec"))
                    ips.append(r.get("from"))
                    rtts.append(r.get("rtt"))

            for nr in obj.get("no_responses", []):
                tx = nr.get("tx")
                if tx:
                    timestamps.append(tx.get("sec"))
                    ips.append(dst)
                    rtts.append(None)

    if not timestamps:
        return pl.DataFrame({"timestamp": [], "ip": [], "rtt": []})

    df = pl.DataFrame({
        "timestamp": timestamps,
        "ip": ips,
        "rtt": rtts,
    })

    # 🔥 fast groupby median
    return (
        df
        .with_columns(pl.from_epoch("timestamp", time_unit="s"))
        .group_by(["timestamp", "ip"])
        .agg(pl.col("rtt").median())
        .sort(["timestamp", "ip"])
    )

def aggregate_ping_file(path: str, tmp_prefix: str | None = None, chunk_lines: int = 50000) -> pd.DataFrame:
    if tmp_prefix is None:
        tmp_dir = tempfile.mkdtemp(prefix="agg_ping_")
    else:
        tmp_dir = tmp_prefix
        os.makedirs(tmp_dir, exist_ok=True)

    # helper to parse a json line fast
    def _loads_line(line: str):
        try:
            return orjson.loads(line)
        except Exception:
            return None

    # accumulator for one chunk: {(timestamp, ip): [rtts]}
    grouped = defaultdict(list)
    tmp_files = []
    lines_in_chunk = 0

    def _flush_chunk():
        nonlocal grouped, lines_in_chunk, tmp_files
        if not grouped:
            return
        records = []
        for (ts, ip), rtts in grouped.items():
            records.append((ts, ip, _median_rtt(rtts)))
        df_chunk = pd.DataFrame.from_records(records, columns=["timestamp", "ip", "rtt"])
        # convert timestamp to datetime on flush to reduce work later
        df_chunk["timestamp"] = pd.to_datetime(df_chunk["timestamp"], unit="s")
        tmp_path = os.path.join(tmp_dir, f"chunk_{len(tmp_files)}.parquet")
        df_chunk.to_parquet(tmp_path, index=False)
        tmp_files.append(tmp_path)
        grouped = defaultdict(list)
        lines_in_chunk = 0

    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.replace("\x00", "").strip()
            if not line:
                continue
            obj = _loads_line(line)
            if obj is None:
                # skip malformed
                continue
            if obj.get("type") != "ping":
                continue
            dst = obj.get("dst")
            for response in obj.get("responses", []):
                grouped[(response.get("tx", {}).get("sec"), response.get("from"))].append(response.get("rtt"))
            for no_response in obj.get("no_responses", []):
                grouped[(no_response.get("tx", {}).get("sec"), dst)].append(None)
            lines_in_chunk += 1
            if lines_in_chunk >= chunk_lines:
                _flush_chunk()

    # flush remainder
    _flush_chunk()

    # if no temp files were produced, return empty frame
    if not tmp_files:
        return pd.DataFrame(columns=["timestamp", "ip", "rtt"])

    # read all chunk parquet files (small now) and combine, then final groupby to merge same keys across chunks
    parts = [pd.read_parquet(p) for p in tmp_files]
    combined = pd.concat(parts, ignore_index=True)
    # group again to combine any (timestamp, ip) across chunks, using _rtt_agg to combine medians
    result = (
        combined.groupby(["timestamp", "ip"], as_index=False)
        .agg({"rtt": _rtt_agg})
        .sort_values(["timestamp", "ip"])
        .reset_index(drop=True)
    )

    # cleanup temp files
    try:
        for p in tmp_files:
            os.remove(p)
        os.rmdir(tmp_dir)
    except Exception:
        pass

    return result



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


def _build_asn_fallback_df_polars(
    sl_df: pl.DataFrame,
    allowed_sec_last_asn: int | None,
) -> pl.DataFrame:
    if sl_df.is_empty() or allowed_sec_last_asn is None:
        return pl.DataFrame({"timestamp": [], "sl_rtt_asn_fallback": []})

    # Reuse existing pandas fallback behavior to preserve ASN prefix matching logic.
    fallback_pd = _build_asn_fallback_df(
        sl_df.select([pl.col("timestamp"), pl.col("sl_ip").alias("ip"), pl.col("sl_rtt").alias("rtt")]).to_pandas(),
        allowed_sec_last_asn,
    )
    if fallback_pd.empty:
        return pl.DataFrame({"timestamp": [], "sl_rtt_asn_fallback": []})

    fallback_pd = fallback_pd.rename(columns={"sl_rtt": "sl_rtt_asn_fallback"})
    return pl.from_pandas(fallback_pd)


def merge_ttl_ping_outputs_polars(
    endpoint_path: str,
    sec_last_path: str,
    mapping_path: str,
    allowed_sec_last_asn: str | int | None = None,
    config_path: str | None = None,
):
    ep_df = aggregate_ping_file_polars(endpoint_path).rename({
        "ip": "ep_ip",
        "rtt": "ep_rtt"
    })

    sl_df = aggregate_ping_file_polars(sec_last_path).rename({
        "ip": "sl_ip",
        "rtt": "sl_rtt"
    })

    mapping_df = pl.read_csv(mapping_path)

    cols = set(mapping_df.columns)

    if {"dst", "sec_last_ip"}.issubset(cols):
        mapping_df = mapping_df.select([
            pl.col("dst").alias("ep_ip"),
            pl.col("sec_last_ip").alias("sl_ip"),
        ])
    elif {"ep_ip", "sl_ip"}.issubset(cols):
        mapping_df = mapping_df.select([
            "ep_ip",
            "sl_ip",
        ])
    else:
        raise ValueError(
            f"mapping file {mapping_path} is missing required columns. "
            "Expected either ['dst', 'sec_last_ip'] or ['ep_ip', 'sl_ip']"
        )

    # match your original behavior
    mapping_df = mapping_df.drop_nulls().unique()
    merged = (
        ep_df
        .join(mapping_df, on="ep_ip", how="left")
        .join(sl_df, on=["timestamp", "sl_ip"], how="left")
    )

    allowed_asn = _resolve_allowed_asn(allowed_sec_last_asn, config_path)
    fallback_df = _build_asn_fallback_df_polars(sl_df, allowed_asn)
    if not fallback_df.is_empty():
        merged = (
            merged
            .join(fallback_df, on="timestamp", how="left")
            .with_columns(
                pl.coalesce([pl.col("sl_rtt"), pl.col("sl_rtt_asn_fallback")]).alias("sl_rtt")
            )
            .drop("sl_rtt_asn_fallback")
        )

    # label logic (vectorized)
    merged = merged.with_columns([
        pl.when(pl.col("ep_rtt").is_null() & pl.col("sl_rtt").is_null())
        .then(pl.lit("dropped"))
        .when(pl.col("ep_rtt").is_not_null() & pl.col("sl_rtt").is_not_null())
        .then(pl.lit("success"))
        .when(pl.col("ep_rtt").is_not_null() & pl.col("sl_rtt").is_null())
        .then(pl.lit("asym"))
        .when(pl.col("ep_rtt").is_null() & pl.col("sl_rtt").is_not_null())
        .then(pl.lit("outage"))
        .otherwise(pl.lit("unknown"))
        .alias("label"),
        pl.when(pl.col("ep_rtt").is_null() & pl.col("sl_rtt").is_null())
        .then(pl.lit(LABEL_MAP["dropped"]))
        .when(pl.col("ep_rtt").is_not_null() & pl.col("sl_rtt").is_not_null())
        .then(pl.lit(LABEL_MAP["success"]))
        .when(pl.col("ep_rtt").is_not_null() & pl.col("sl_rtt").is_null())
        .then(pl.lit(LABEL_MAP["asym"]))
        .when(pl.col("ep_rtt").is_null() & pl.col("sl_rtt").is_not_null())
        .then(pl.lit(LABEL_MAP["outage"]))
        .otherwise(pl.lit(None, pl.Int64))
        .alias("label_num"),
    ])

    return (
        merged
        .select(["timestamp", "ep_ip", "sl_ip", "ep_rtt", "sl_rtt", "label", "label_num"])
        .sort(["timestamp", "ep_ip"])
    )

def merge_ttl_ping_outputs(
    endpoint_path: str,
    sec_last_path: str,
    mapping_path: str,
    allowed_sec_last_asn: str | int | None = None,
    config_path: str | None = None,
) -> pd.DataFrame:

    with ProcessPoolExecutor(2) as ex:
        ep_future = ex.submit(aggregate_ping_file, endpoint_path)
        sl_future = ex.submit(aggregate_ping_file, sec_last_path)

        ep_df = ep_future.result()
        sl_df = sl_future.result()
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
        print("[CLEAN] DataFrame is empty, skipping cleaning.")
        return df.copy()

    cleaned = df.copy()

    responsive_sl_ips = cleaned.loc[
        cleaned["sl_rtt"].notna(),
        "sl_ip",
    ].dropna().unique()
    if len(responsive_sl_ips) != cleaned["sl_ip"].nunique(dropna=True):
        cleaned = cleaned[
            cleaned["sl_ip"].isna() | cleaned["sl_ip"].isin(responsive_sl_ips)
        ].copy()
        if cleaned.empty:
            return cleaned.reset_index(drop=True)

    successful_ep_ips = cleaned.loc[
        cleaned["label"] == "success",
        "ep_ip",
    ].dropna().unique()
    if len(successful_ep_ips) != cleaned["ep_ip"].nunique(dropna=True):
        cleaned = cleaned[cleaned["ep_ip"].isin(successful_ep_ips)].copy()

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

    print(f"[PROCESS] Processing bucket with endpoint: {endpoint_path}, sec_last: {sec_last_path}, mapping: {mapping_path}")
    merged_df = merge_ttl_ping_outputs_polars(
        endpoint_path,
        sec_last_path,
        mapping_path,
        allowed_sec_last_asn=allowed_sec_last_asn,
        config_path=config_path,
    )
    print("[PROCESS] Merged dataframe before cleaning:")
    print(merged_df)

    # cleaned_df = clean_merged_dataframe(merged_df.to_pandas())
    # print("[PROCESS] Cleaned merged dataframe:")
    # print(cleaned_df)

    merged_df.to_csv(filtered_output_path, index=False)
    print(f"[PROCESS] Finished processing. Output saved to {filtered_output_path}")

    return filtered_output_path
