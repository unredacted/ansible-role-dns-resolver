"""Filters for ansible-role-dns-resolver (standard library only)."""

import base64


def dnskey_tag(flags, protocol, algorithm, public_key_b64):
    """Key tag of a DNSKEY record, as defined in RFC 4034 appendix B."""
    rdata = (
        int(flags).to_bytes(2, "big")
        + int(protocol).to_bytes(1, "big")
        + int(algorithm).to_bytes(1, "big")
        + base64.b64decode(public_key_b64)
    )
    total = 0
    for i, byte in enumerate(rdata):
        total += byte if i % 2 else byte << 8
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


def dnskey_tags(zone_text):
    """Key tags of every DNSKEY record in zone-file text (one record per line)."""
    tags = []
    for line in zone_text.splitlines():
        line = line.split(";", 1)[0].strip()
        fields = line.split()
        if "DNSKEY" not in fields:
            continue
        rest = fields[fields.index("DNSKEY") + 1 :]
        if len(rest) < 4:
            continue
        flags, protocol, algorithm = rest[:3]
        tags.append(dnskey_tag(flags, protocol, algorithm, "".join(rest[3:])))
    return tags


class FilterModule:
    def filters(self):
        return {"dns_resolver_dnskey_tags": dnskey_tags}
