#!/usr/bin/env python3
"""
Streamlined probe analysis script based on test_probe_analysis.ipynb.
"""

import argparse
import json
from pathlib import Path

DEFAULT_DATA_DIR = Path("/data/lake/rhh/raw/rhh/2026/04/22/test_probes")
DEFAULT_SAMPLE_GLOB = "/home/mandat/test_probe*.json"
DEFAULT_OUTPUT = Path("filtered_ips.txt")
RATE_COLUMNS = [0.1, 0.2, 0.5, 1.0]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze probe ping outputs and save the IPs to keep."
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help=(
            "JSON files, directories, or glob patterns to analyze. If omitted, "
            "the script uses the notebook defaults."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="CSV file to write the IPs to keep. Default: %(default)s",
    )
    return parser.parse_args()


def extract_rate_seconds(record: dict) -> float:
    wait_seconds = record.get("wait", 0) or 0
    wait_microseconds = record.get("wait_us", 0) or 0
    return float(wait_seconds) + (float(wait_microseconds) / 1_000_000)


def discover_input_files(inputs: list[str]) -> list[Path]:
    if inputs:
        files: set[Path] = set()
        for raw_input in inputs:
            candidate = Path(raw_input)
            if candidate.is_dir():
                files.update(candidate.glob("*.json"))
                continue
            if candidate.is_file():
                files.add(candidate)
                continue
            files.update(Path().glob(raw_input))
        return sorted(path.resolve() for path in files)

    if DEFAULT_DATA_DIR.exists():
        return sorted(DEFAULT_DATA_DIR.glob("*.json"))

    return sorted(Path("/").glob(DEFAULT_SAMPLE_GLOB.lstrip("/")))


def iter_ping_rows(json_path: Path):
    with json_path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue

            record = json.loads(line)
            if record.get("type") != "ping":
                continue

            stats = record.get("statistics", {})
            yield {
                "source_file": json_path.name,
                "dst": record.get("dst"),
                "rate_seconds": extract_rate_seconds(record),
                "replies": stats.get("replies"),
                "loss": stats.get("loss"),
                "min": stats.get("min"),
                "max": stats.get("max"),
                "avg": stats.get("avg"),
                "stddev": stats.get("stddev"),
            }


def build_dataframe(input_files: list[Path]) -> list[dict]:
    rows = []
    for json_path in input_files:
        rows.extend(iter_ping_rows(json_path))

    return sorted(
        rows,
        key=lambda row: (
            row.get("dst") or "",
            row.get("rate_seconds") or 0,
            row.get("source_file") or "",
        ),
    )


def linearity_metrics(losses_by_rate: dict[float, float]) -> dict[str, float]:
    x = [float(rate) for rate in RATE_COLUMNS]
    y = [float(losses_by_rate[rate]) for rate in RATE_COLUMNS]

    x_mean = sum(x) / len(x)
    y_mean = sum(y) / len(y)
    numerator = sum((x_i - x_mean) * (y_i - y_mean) for x_i, y_i in zip(x, y))
    denominator = sum((x_i - x_mean) ** 2 for x_i in x)
    m = numerator / denominator if denominator else 0.0
    b = y_mean - (m * x_mean)

    y_hat = [(m * x_i) + b for x_i in x]
    ss_res = sum((y_i - y_hat_i) ** 2 for y_i, y_hat_i in zip(y, y_hat))
    ss_tot = sum((y_i - y_mean) ** 2 for y_i in y)
    r2 = 1 - ss_res / ss_tot if ss_tot != 0 else 1.0

    return {
        "slope": m,
        "intercept": b,
        "r2": r2,
        "max_abs_resid": max(abs(y_i - y_hat_i) for y_i, y_hat_i in zip(y, y_hat)),
    }


def compute_ips_to_keep(rows: list[dict]) -> list[str]:
    if not rows:
        return []

    all_ips = {row["dst"] for row in rows if row.get("dst")}
    ips_to_filter: set[str] = set()

    ips_to_filter.update(
        row["dst"] for row in rows if row.get("dst") and row.get("loss") == 1
    )

    filtered_rows = [
        row
        for row in rows
        if row.get("dst") and row.get("loss") is not None and row.get("loss") < 1
    ]
    if not filtered_rows:
        return sorted(all_ips - ips_to_filter)

    loss_by_rate: dict[str, dict[float, float]] = {}
    for row in filtered_rows:
        dst = row["dst"]
        loss_by_rate.setdefault(dst, {})[float(row["rate_seconds"])] = float(row["loss"])

    complete_loss_by_rate: dict[str, dict[float, float]] = {}
    for dst, rates in loss_by_rate.items():
        if set(RATE_COLUMNS).issubset(rates):
            complete_loss_by_rate[dst] = rates
        else:
            ips_to_filter.add(dst)

    if not complete_loss_by_rate:
        return sorted(all_ips - ips_to_filter)

    for dst, rates in complete_loss_by_rate.items():
        metrics = linearity_metrics(rates)
        has_loss_pattern = rates[0.1] > 0 and (
            rates[0.2] > 0 or rates[0.5] > 0 or rates[1.0] > 0
        )
        flagged_linear = (
            has_loss_pattern
            and metrics["slope"] < -0.8
            and rates[0.1] > 0.05
            and metrics["r2"] >= 0.85
        )
        if flagged_linear:
            ips_to_filter.add(dst)

    return sorted(all_ips - ips_to_filter)


def write_ips_to_csv(ips_to_keep: list[str], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    contents = "\n".join(ips_to_keep)
    if ips_to_keep:
        contents += "\n"
    output_path.write_text(contents, encoding="utf-8")


def main() -> int:
    args = parse_args()
    input_files = discover_input_files(args.inputs)
    if not input_files:
        raise FileNotFoundError("No input JSON files found.")

    df = build_dataframe(input_files)
    ips_to_keep = compute_ips_to_keep(df)
    write_ips_to_csv(ips_to_keep, args.output)

    print(f"Analyzed {len(input_files)} files")
    print(f"Found {len({row['dst'] for row in df if row.get('dst')})} unique IPs")
    print(f"Keeping {len(ips_to_keep)} IPs")
    print(f"Saved IPs to keep to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
