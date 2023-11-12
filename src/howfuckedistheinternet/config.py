max_history = 4             # 2hrs at regular 30min updates
update_frequency = 1800     # 30 mins
write_sql_enabled = True
debug = True

headers = {"User-Agent": "howfuckedistheinternet.com"}

aws_v4_file = "aws_ec2_checkpoints.json"
aws_v6_file = "aws_ec2_checkpointsv6.json"
html_root = "/var/www/howfuckedistheinternet.com/html/"
sqlitedb = "howfucked.db"

# Adjust metric weighting based on importance
# threshold unit for literal measurements is %; measurements using historic averages have no thresholds
# Frequency to check each measurement type (seconds)
metrics = {
    "origins": {
        "enabled": True,
        "weight": 0.1,
        "threshold": None,
        "freq": 1800,
        "descr": "Number of origin AS per prefix",
    },
    "bogonASNs": {
        "enabled": True,
        "weight": 0.01,
        "threshold": 100,       # Measured in visibility of bgp.tools contributors
        "freq": 1800,
        "descr": "Prefixes originated by private or invalid ASNs",
    },
    "prefixes": {
        "enabled": True,
        "weight": 0.2,
        "threshold": 85,
        "freq": 1800,
        "descr": "Dramatic decrease in advertised prefixes by an AS",
    },
    "dns_root": {
        "enabled": True,
        "weight": 10,
        "threshold": 10,
        "freq": 1800,
        "descr": "DNS root-server reachability using RIPE Atlas",
    },
    "atlas_connected": {
        "enabled": True,
        "weight": 1,
        "threshold": 20,
        "freq": 1800,
        "descr": "RIPE Atlas probe connected status",
    },
    "invalid_roa": {
        "enabled": True,
        "weight": 1,
        "threshold": None,
        "freq": 1800,
        "descr": "RPKI ROA validity",
    },
    "total_roa": {
        "enabled": True,
        "weight": 5,
        "threshold": 90,
        "freq": 1800,
        "descr": "Dramatic decrease in published RPKI ROAs",
    },
    "dfz": {
        "enabled": True,
        "weight": 3,
        "threshold": 1,
        "freq": 1800,
        "descr": "Dramatic increase or decrease of DFZ size",
    },
    "ntp": {
        "enabled": True,
        "weight": 2,
        "threshold": 30,
        "freq": 1800,
        "descr": "NTP Pool Project checks using RIPE Atlas",
    },
    "public_dns": {
        "enabled": True,
        "weight": 5,
        "threshold": 25,
        "freq": 1800,
        "descr": "Public DNS resolver checks using RIPE Atlas",
    },
    "aws": {
        "enabled": True,
        "weight": 6,
        "threshold": 10,
        "freq": 1800,
        "descr": "AWS connectivity checks",
    },
    "gcp": {
        "enabled": True,
        "weight": 1,
        "threshold": 1,
        "freq": 1800,  # gcp weight is scaled dynamically
        "descr": "GCP Incident Notifications",
    },
    "tls": {
        "enabled": True,
        "weight": 1,
        "threshold": 10,
        "freq": 1800,
        "descr": "TLS cert validation of popular sites, using RIPE Atlas",
    },
    "cloudflare": {
        "enabled": True,
        "weight": 1,
        "threshold": None,
        "freq": 1800,
        "descr": "Open Cloudflare incidents"
    },
    "slack": {
        "enabled": True,
        "weight": 1,
        "threshold": None,
        "freq": 1800,
        "descr": "Open Slack incidents"
    },
    "discord": {
        "enabled": True,
        "weight": 1,
        "threshold": None,
        "freq": 1800,
        "descr": "Open Discord incidents"
    },
}