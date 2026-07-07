import csv
import io
import ipaddress
import subprocess
from pathlib import Path


SUMMARY_FIELDS = [
    "frame.number",
    "frame.time",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "_ws.col.Protocol",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "http.host",
    "http.request.method",
    "tls.handshake.extensions_server_name",
    "_ws.col.Info",
]


def endpoint_filter(alert):
    filters = []
    for key in ("src_ip", "dest_ip"):
        value = alert.get(key) if alert else None
        if not value:
            continue
        try:
            parsed = ipaddress.ip_address(str(value))
        except ValueError:
            continue
        field = "ipv6.addr" if parsed.version == 6 else "ip.addr"
        expression = f"{field} == {parsed}"
        if expression not in filters:
            filters.append(expression)
    return " or ".join(filters)


def tshark_command(pcap_path, limit, display_filter=None):
    command = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
    ]
    if display_filter:
        command.extend(["-Y", display_filter])
    for field in SUMMARY_FIELDS:
        command.extend(["-e", field])
    return command


def normalize_csv(text, limit):
    rows = list(csv.reader(text.splitlines()))
    if rows:
        rows = rows[: limit + 1]
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerows(rows)
    return output.getvalue().strip()


def packet_count(text):
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return 0
    return max(0, len(lines) - 1)


def summarize_pcap(pcap_path, output_path, limit=200, alert=None, timeout=20):
    display_filter = endpoint_filter(alert)
    command = tshark_command(pcap_path, limit, display_filter)
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
    normalized = normalize_csv(result.stdout, limit)

    if display_filter and packet_count(normalized) == 0:
        command = tshark_command(pcap_path, limit, None)
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
        normalized = normalize_csv(result.stdout, limit)
        display_filter = ""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(normalized + "\n", encoding="utf-8")
    return {
        "path": str(output),
        "packet_count": packet_count(normalized),
        "display_filter": display_filter,
        "status": "generated",
    }
