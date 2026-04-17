import configparser
import os

DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__),
    "config.ini"
)

def load_config(config_path: str = DEFAULT_CONFIG_PATH) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    loaded_files = config.read(config_path)
    if not loaded_files:
        raise FileNotFoundError(f"Could not read config file: {config_path}")
    return config


def get_runtime_settings(config_path: str = DEFAULT_CONFIG_PATH) -> dict:
    config = load_config(config_path)
    return {
        "src_ips": [
            ip.strip()
            for ip in config.get("network", "src_ips").split(",")
            if ip.strip()
        ],
        "src_ips_v6": [
            ip.strip()
            for ip in config.get("network", "src_ips_v6").split(",")
            if ip.strip()
        ],
        "asn": config.get("asn", "asn"),
        "bq_project_id": config.get("bigquery", "project_id"),
        "input_ip_file": config.get("input", "input_ip_file", fallback=None),
        "output_dir": config.get("output", "output_dir"),
        "sat_hop": config.getint("traceroute", "sat_hop", fallback=-2),
    }


_settings = get_runtime_settings()

# ---------- NETWORK ----------
SRC_IPS = [
    ip
    for ip in _settings["src_ips"]
]

SRC_IPS_V6 = [
    ip
    for ip in _settings["src_ips_v6"]
]

# ---------- ASN ----------
ASN = _settings["asn"]

# ---------- BIGQUERY ----------
BQ_PROJECT_ID = _settings["bq_project_id"]

# ---------- INPUT ----------
INPUT_IP_FILE = _settings["input_ip_file"]

# ---------- OUTPUT ----------
OUTPUT_DIR = _settings["output_dir"]

# ---------- TRACEROUTE ----------
SAT_HOP = _settings["sat_hop"]
