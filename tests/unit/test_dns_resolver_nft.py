import importlib.util
import json
import pathlib
import unittest

_PATH = pathlib.Path(__file__).resolve().parents[2] / "filter_plugins" / "dns_resolver_nft.py"
_SPEC = importlib.util.spec_from_file_location("dns_resolver_nft", _PATH)
plugin = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(plugin)


def listing(meter_elems, pilot_elems, handle=1, rule_expr="drop"):
    return json.dumps({"nftables": [
        {"metainfo": {"version": "1.1.3"}},
        {"table": {"family": "inet", "name": "dns_resolver", "handle": handle}},
        {"set": {"family": "inet", "name": "meter4", "table": "dns_resolver", "type": "ipv4_addr",
                 "handle": handle + 1, "flags": ["timeout", "dynamic"], "elem": meter_elems}},
        {"set": {"family": "inet", "name": "pilot4", "table": "dns_resolver", "type": "ipv4_addr",
                 "handle": handle + 2, "flags": "interval", "elem": pilot_elems}},
        {"rule": {"family": "inet", "table": "dns_resolver", "chain": "input",
                  "handle": handle + 3, "expr": [{rule_expr: None}]}},
    ]})


class Fingerprint(unittest.TestCase):
    def test_ignores_handles_and_dynamic_entries(self):
        a = plugin.nft_fingerprint(listing([], ["192.0.2.0/24"]))
        b = plugin.nft_fingerprint(listing(["198.51.100.7"], ["192.0.2.0/24"], handle=40))
        self.assertTrue(a)
        self.assertEqual(a, b)

    def test_sees_static_set_and_rule_changes(self):
        base = plugin.nft_fingerprint(listing([], ["192.0.2.0/24"]))
        more_pilot = listing([], ["192.0.2.0/24", "203.0.113.9"])
        other_rule = listing([], ["192.0.2.0/24"], rule_expr="accept")
        self.assertNotEqual(base, plugin.nft_fingerprint(more_pilot))
        self.assertNotEqual(base, plugin.nft_fingerprint(other_rule))

    def test_missing_table_gives_empty(self):
        self.assertEqual(plugin.nft_fingerprint(""), "")
        self.assertEqual(plugin.nft_fingerprint('{"nftables": [{"metainfo": {}}]}'), "")


if __name__ == "__main__":
    unittest.main()
