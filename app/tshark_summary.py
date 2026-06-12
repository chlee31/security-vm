import csv
import subprocess
from pathlib import Path


def summarize_pcap(pcap_path, output_path, limit=200):
    command = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-e",
        "frame.time",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
        "-e",
        "dns.qry.name",
        "-E",
        "header=y",
        "-E",
        "separator=,",
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    rows = list(csv.reader(result.stdout.splitlines()))[:limit]
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(",".join(row) for row in rows), encoding="utf-8")
    return str(output)
