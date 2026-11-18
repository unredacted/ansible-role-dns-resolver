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


# DNS stamps: https://dnscrypt.info/stamps-specifications/
_PROTOCOLS = {"dnscrypt": 0x01, "doh": 0x02, "dot": 0x03, "doq": 0x04}
_PROPS = {"dnssec": 1, "nolog": 2, "nofilter": 4}


def _lp(value):
    data = value.encode() if isinstance(value, str) else bytes(value)
    if len(data) > 255:
        raise ValueError("stamp field longer than 255 bytes")
    return bytes([len(data)]) + data


def _vlp(items):
    if not items:
        return b"\x00"
    out = b""
    for i, item in enumerate(items):
        data = bytes(item)
        length = len(data) | (0x80 if i < len(items) - 1 else 0)
        out += bytes([length]) + data
    return out


def _address(address, port, default_port):
    host = f"[{address}]" if ":" in address else address
    return host if int(port) == default_port else f"{host}:{port}"


def dns_stamp(protocol, address, port, hostname="", path="/dns-query", provider_pubkey="",
              provider_name="", dnssec=True, nolog=True, nofilter=True):
    """Build an sdns:// stamp for a DNSCrypt, DoH, DoT or DoQ server."""
    props = (dnssec and _PROPS["dnssec"]) | (nolog and _PROPS["nolog"]) | (
        nofilter and _PROPS["nofilter"])
    out = bytes([_PROTOCOLS[protocol]]) + int(props).to_bytes(8, "little")
    if protocol == "dnscrypt":
        out += _lp(_address(address, port, 443))
        out += _lp(bytes.fromhex(provider_pubkey)) + _lp(provider_name)
    elif protocol == "doh":
        out += _lp(_address(address, port, 443)) + _vlp([]) + _lp(hostname) + _lp(path)
    else:
        out += _lp(_address(address, port, 853)) + _vlp([]) + _lp(hostname)
    return "sdns://" + base64.urlsafe_b64encode(out).rstrip(b"=").decode()


class FilterModule:
    def filters(self):
        return {
            "dns_resolver_dnskey_tags": dnskey_tags,
            "dns_resolver_stamp": dns_stamp,
        }
