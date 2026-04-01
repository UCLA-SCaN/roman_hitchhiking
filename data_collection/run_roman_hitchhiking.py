import argparse
from config import ASN, OUTPUT_DIR
from run_scamper import ttl_ping

"""
Runs Roman HitchHiking
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Roman HitchHiking")

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

    args = parser.parse_args()

    ttl_ping(
        asn=ASN, 
        wait_probe=args.probe_interval, 
        num_probes=args.num_probes,
        output_dir=OUTPUT_DIR,
        name=args.name,
    )
