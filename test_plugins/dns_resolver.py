"""Small address and name checks used by ansible-role-dns-resolver.

These are Jinja2 tests. They use only the Python standard library, so the
role does not need netaddr or ansible.utils on the controller.
"""

import ipaddress
import re

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def valid_ip(value, version=None):
    """True if value is a single IP address (no prefix), optionally of one version."""
    if not isinstance(value, str) or "/" in value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return version is None or address.version == int(version)


def valid_network(value, version=None):
    """True if value is an IP address or a network in CIDR form."""
    if not isinstance(value, str):
        return False
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return version is None or network.version == int(version)


def valid_hostname(value):
    """True if value is a fully qualified DNS name with at least two labels."""
    if not isinstance(value, str):
        return False
    name = value.lower().rstrip(".")
    if not name or len(name) > 253:
        return False
    labels = name.split(".")
    return len(labels) >= 2 and all(_LABEL.match(label) for label in labels)


class TestModule:
    def tests(self):
        return {
            "dns_resolver_valid_ip": valid_ip,
            "dns_resolver_valid_network": valid_network,
            "dns_resolver_valid_hostname": valid_hostname,
        }
