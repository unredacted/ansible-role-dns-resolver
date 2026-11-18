import importlib.util
import pathlib
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
_PATH = _HERE.parents[1] / "filter_plugins" / "dns_resolver_filters.py"
_SPEC = importlib.util.spec_from_file_location("dns_resolver_filters", _PATH)
plugin = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(plugin)


class DnskeyTags(unittest.TestCase):
    def test_root_trust_anchor_from_debian(self):
        # Debian 13's dns-root-data root.key holds KSK-2017 and KSK-2024.
        text = (_HERE / "data" / "root.key").read_text()
        self.assertEqual(sorted(plugin.dnskey_tags(text)), [20326, 38696])

    def test_ignores_comments_and_other_records(self):
        text = "; a comment with DNSKEY in it\n. IN DS 20326 8 2 abcd\n"
        self.assertEqual(plugin.dnskey_tags(text), [])


if __name__ == "__main__":
    unittest.main()
