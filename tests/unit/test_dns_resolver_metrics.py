import importlib.util
import json
import pathlib
import unittest
from unittest import mock

_HERE = pathlib.Path(__file__).resolve().parent
_PATH = _HERE.parents[1] / "files" / "dns-resolver-metrics.py"
_SPEC = importlib.util.spec_from_file_location("dns_resolver_metrics", _PATH)
metrics = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(metrics)


def chain_json(*rules):
    items = [{"metainfo": {}}, {"chain": {"name": "service"}}]
    for comment, packets in rules:
        rule = {"expr": [{"counter": {"packets": packets, "bytes": packets * 100}}, {"drop": None}]}
        if comment:
            rule["comment"] = comment
        items.append({"rule": rule})
    return json.dumps({"nftables": items})


class FirewallDrops(unittest.TestCase):
    def test_sums_counters_per_label_and_skips_unlabelled_rules(self):
        output = chain_json(("pilot", 3), ("pilot", 4), ("packet_rate", 5), (None, 99))
        result = mock.Mock(returncode=0, stdout=output)
        with mock.patch.object(metrics.subprocess, "run", return_value=result):
            totals = metrics.firewall_drops()
        # Three chains are read; each returns the same rules here.
        self.assertEqual(totals["pilot"], (21, 2100))
        self.assertEqual(totals["packet_rate"], (15, 1500))
        self.assertNotIn(None, totals)


class TrustAnchor(unittest.TestCase):
    def test_reads_debian_root_key(self):
        tags = metrics.trust_anchor_tags(str(_HERE / "data" / "root.key"))
        self.assertEqual(sorted(tags), [20326, 38696])


if __name__ == "__main__":
    unittest.main()
