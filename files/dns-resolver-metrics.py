#!/usr/bin/python3
"""Write host metrics for the DNS resolver to the node_exporter textfile directory.

Usage: dns-resolver-metrics.py <textfile dir> <trust anchor file> <unit>...

Writes dns_resolver_host.prom with:
  - packets dropped by the firewall, per rule label (rate limits, pilot list,
    plain port, egress rules). Only rule counters are read, never the sets
    that hold per-source addresses.
  - restarts, state and memory of each DNS service.
  - the key tags in the root trust anchor file.
All values are totals; nothing names a client or a query.
"""

import base64
import json
import os
import subprocess
import sys
import time

TABLE = ("inet", "dns_resolver")
CHAINS = ("input", "service", "output")


def firewall_drops():
    totals = {}
    for chain in CHAINS:
        result = subprocess.run(
            ["nft", "-j", "list", "chain", *TABLE, chain],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            continue
        for item in json.loads(result.stdout).get("nftables", []):
            rule = item.get("rule")
            if not rule or not rule.get("comment"):
                continue
            for expr in rule.get("expr", []):
                counter = expr.get("counter") if isinstance(expr, dict) else None
                if counter:
                    label = rule["comment"]
                    packets, octets = totals.get(label, (0, 0))
                    totals[label] = (packets + counter["packets"], octets + counter["bytes"])
    return totals


def unit_state(unit):
    result = subprocess.run(
        ["systemctl", "show", unit, "-p", "NRestarts", "-p", "ActiveState",
         "-p", "MemoryCurrent", "-p", "MemoryMax"],
        capture_output=True, text=True, check=False,
    )
    props = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)

    def number(key):
        value = props.get(key, "")
        return int(value) if value.isdigit() else None

    return {
        "active": 1 if props.get("ActiveState") == "active" else 0,
        "restarts": number("NRestarts"),
        "memory": number("MemoryCurrent"),
        "memory_max": number("MemoryMax"),
    }


def dnskey_tag(flags, protocol, algorithm, key_b64):
    rdata = (int(flags).to_bytes(2, "big") + int(protocol).to_bytes(1, "big")
             + int(algorithm).to_bytes(1, "big") + base64.b64decode(key_b64))
    total = sum(byte if i % 2 else byte << 8 for i, byte in enumerate(rdata))
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


def trust_anchor_tags(path):
    tags = []
    try:
        text = open(path).read()
    except OSError:
        return tags
    for line in text.splitlines():
        fields = line.split(";", 1)[0].split()
        if "DNSKEY" in fields:
            rest = fields[fields.index("DNSKEY") + 1:]
            if len(rest) >= 4:
                tags.append(dnskey_tag(rest[0], rest[1], rest[2], "".join(rest[3:])))
    return tags


def main(textfile_dir, anchor_file, *units):
    lines = [
        "# HELP dns_resolver_firewall_dropped_packets_total Packets dropped, per firewall rule.",
        "# TYPE dns_resolver_firewall_dropped_packets_total counter",
        "# HELP dns_resolver_firewall_dropped_bytes_total Bytes dropped, per firewall rule.",
        "# TYPE dns_resolver_firewall_dropped_bytes_total counter",
    ]
    for label, (packets, octets) in sorted(firewall_drops().items()):
        lines.append(f'dns_resolver_firewall_dropped_packets_total{{rule="{label}"}} {packets}')
        lines.append(f'dns_resolver_firewall_dropped_bytes_total{{rule="{label}"}} {octets}')

    lines += [
        "# HELP dns_resolver_service_active 1 if the service is running.",
        "# TYPE dns_resolver_service_active gauge",
        "# HELP dns_resolver_service_restarts Automatic restarts since the service was started.",
        "# TYPE dns_resolver_service_restarts gauge",
    ]
    for unit in units:
        state = unit_state(unit)
        lines.append(f'dns_resolver_service_active{{unit="{unit}"}} {state["active"]}')
        for key, metric in (("restarts", "restarts"), ("memory", "memory_bytes"),
                            ("memory_max", "memory_max_bytes")):
            if state[key] is not None:
                lines.append(f'dns_resolver_service_{metric}{{unit="{unit}"}} {state[key]}')

    lines.append("# HELP dns_resolver_trust_anchor_key Root key tags in the trust anchor file.")
    lines.append("# TYPE dns_resolver_trust_anchor_key gauge")
    for tag in sorted(set(trust_anchor_tags(anchor_file))):
        lines.append(f'dns_resolver_trust_anchor_key{{tag="{tag}"}} 1')

    lines.append(f"dns_resolver_metrics_timestamp_seconds {int(time.time())}")

    if not os.path.isdir(textfile_dir):
        return 0
    target = os.path.join(textfile_dir, "dns_resolver_host.prom")
    with open(target + ".tmp", "w") as handle:
        handle.write("\n".join(lines) + "\n")
    os.chmod(target + ".tmp", 0o644)
    os.replace(target + ".tmp", target)
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
