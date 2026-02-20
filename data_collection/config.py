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

# ---------- AUTH ----------
IPINFO_TOKEN = config.get("auth", "ipinfo_token")

# ---------- ASN ----------
STARLINK_ASN = config.get("asn", "starlink_asn")
HURRICANE_ELECTRIC_ASN = config.get("asn", "hurricane_electric_asn")