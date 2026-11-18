"""Fingerprint of the live dns_resolver nftables table.

Takes the output of `nft -j -s list table inet dns_resolver` and returns a
sha256 of the rules, chains and sets, leaving out what changes on its own:
object handles, counter values (-s), and the entries of dynamic sets (the
per-source rate-limit state). Standard library only.
"""

import hashlib
import json


def nft_fingerprint(text):
    try:
        items = json.loads(text).get("nftables", [])
    except (TypeError, ValueError, AttributeError):
        return ""
    kept = []
    for item in items:
        if not isinstance(item, dict) or len(item) != 1 or "metainfo" in item:
            continue
        ((kind, body),) = item.items()
        body = {key: value for key, value in body.items() if key != "handle"}
        flags = body.get("flags", [])
        if isinstance(flags, str):
            flags = [flags]
        if kind == "set" and "dynamic" in flags:
            body.pop("elem", None)
        kept.append({kind: body})
    if not kept:
        return ""
    return hashlib.sha256(json.dumps(kept, sort_keys=True).encode()).hexdigest()


class FilterModule:
    def filters(self):
        return {"dns_resolver_nft_fingerprint": nft_fingerprint}
