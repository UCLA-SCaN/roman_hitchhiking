import argparse

from config import DEFAULT_CONFIG_PATH, get_runtime_settings
from run_scamper import ttl_ping


def run_roman_hitchhiking(
    name: str | None,
    asn: str,
    probe_interval: int,
    num_probes: int,
    output_dir: str,
    v6: bool = False,
    config_path: str = DEFAULT_CONFIG_PATH,
    src_ips: list[str] | None = None,
) -> None:
    ttl_ping_kwargs = {
        "asn": asn,
        "wait_probe": probe_interval,
        "num_probes": num_probes,
        "output_dir": output_dir,
        "name": name,
    }
    if v6:
        ttl_ping_kwargs["v6"] = v6
    if config_path != DEFAULT_CONFIG_PATH:
        ttl_ping_kwargs["config_path"] = config_path
    if src_ips is not None:
        ttl_ping_kwargs["src_ips"] = src_ips

    ttl_ping(
        **ttl_ping_kwargs,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Roman HitchHiking")

    parser.add_argument(
        "--config",
        type=str,
        default=DEFAULT_CONFIG_PATH,
        help="Path to the config.ini file.",
    )

    parser.add_argument(
        "--name",
        type=str,
        default=None,
        # required=True,
        help="name of measurement (e.g. name of network)",
    )

    parser.add_argument(
        "--probe-interval",
        type=int,
        required=True,
        help="Seconds between probes"
    )

    parser.add_argument(
        "--num-probes",
        type=int,
        required=True,
        help="Number of probes (0 = continuous)"
    )

    parser.add_argument(
        "--v6",
        default=False,
        help="Whether to use IPv6 addresses (from config) instead of IPv4."
    )

    args = parser.parse_args()
    settings = get_runtime_settings(args.config)

    run_roman_hitchhiking(
        name=args.name,
        asn=settings["asn"],
        probe_interval=args.probe_interval,
        num_probes=args.num_probes,
        output_dir=settings["output_dir"],
        v6=args.v6,
        config_path=args.config,
        src_ips=settings["src_ips_v6"] if args.v6 else settings["src_ips"],
    )
