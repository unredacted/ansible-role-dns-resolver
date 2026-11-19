#!/usr/bin/python3
"""Add and remove ACME DNS-01 TXT records in Cloudflare for lego's exec provider.

Debian's lego package is built without its Cloudflare provider. With
dns_resolver_acme_provider: exec and dns_resolver_acme_exec_hook: cloudflare,
the role installs this script and lego calls it:

  cloudflare.py present <fqdn> <value>
  cloudflare.py cleanup <fqdn> <value>

lego follows an _acme-challenge CNAME first, so with a delegated challenge
zone <fqdn> is the name in that zone. The zone is found by asking Cloudflare
for each parent name in turn, with the token in CF_DNS_API_TOKEN (Zone:Read
and DNS:Edit on that zone). Standard library only. The token is never
printed.
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.cloudflare.com/client/v4"
TTL = 60


class HookError(Exception):
    pass


def call(method, path, token, params=None, body=None):
    url = API + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            reply = json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            reply = json.load(exc)
        except ValueError:
            raise HookError(f"{method} {path}: HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise HookError(f"{method} {path}: {exc}") from None
    if not reply.get("success"):
        messages = [e.get("message", "?") for e in reply.get("errors", [])]
        errors = "; ".join(messages) or "unknown error"
        raise HookError(f"{method} {path}: {errors}")
    return reply.get("result")


def find_zone(name, token):
    labels = name.rstrip(".").split(".")
    for start in range(len(labels) - 1):
        candidate = ".".join(labels[start:])
        zones = call("GET", "/zones", token, {"name": candidate})
        if zones:
            return zones[0]["id"], candidate
    raise HookError(f"no Cloudflare zone visible to the token contains {name}")


def present(name, value, token):
    zone_id, zone = find_zone(name, token)
    existing = call("GET", f"/zones/{zone_id}/dns_records", token,
                    {"type": "TXT", "name": name, "content": value})
    if existing:
        print(f"TXT record for {name} already in {zone}")
        return
    call("POST", f"/zones/{zone_id}/dns_records", token,
         body={"type": "TXT", "name": name, "content": value, "ttl": TTL})
    print(f"added TXT record for {name} in {zone}")


def cleanup(name, value, token):
    zone_id, zone = find_zone(name, token)
    records = call("GET", f"/zones/{zone_id}/dns_records", token,
                   {"type": "TXT", "name": name, "content": value})
    for record in records or []:
        call("DELETE", f"/zones/{zone_id}/dns_records/{record['id']}", token)
    print(f"removed {len(records or [])} TXT record(s) for {name} from {zone}")


def main(argv):
    if len(argv) != 3 or argv[0] not in ("present", "cleanup"):
        print(__doc__, file=sys.stderr)
        return 2
    token = os.environ.get("CF_DNS_API_TOKEN", "").strip()
    if not token:
        print("CF_DNS_API_TOKEN is not set", file=sys.stderr)
        return 2
    action, fqdn, value = argv
    name = fqdn.rstrip(".")
    try:
        (present if action == "present" else cleanup)(name, value, token)
    except HookError as exc:
        print(f"cloudflare hook: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
