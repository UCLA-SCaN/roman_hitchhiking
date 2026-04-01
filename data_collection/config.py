import configparser
import os

CONFIG_PATH = os.path.join(
    os.path.dirname(__file__),
    "config.ini"
)

config = configparser.ConfigParser()
config.read(CONFIG_PATH)

# ---------- NETWORK ----------
SRC_IPS = [
    ip.strip()
    for ip in config.get("network", "src_ips").split(",")
]

# ---------- ASN ----------
ASN = config.get("asn", "asn")

# ---------- BIGQUERY ----------
BQ_PROJECT_ID = config.get("bigquery", "project_id")

# ---------- INPUT ----------
INPUT_IP_FILE = config.get("input", "input_ip_file", fallback=None)

# ---------- OUTPUT ----------
OUTPUT_DIR = config.get("output", "output_dir")
