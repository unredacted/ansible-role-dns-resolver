import importlib.util
import pathlib
import unittest

_PATH = pathlib.Path(__file__).resolve().parents[2] / "test_plugins" / "dns_resolver.py"
_SPEC = importlib.util.spec_from_file_location("dns_resolver_tests", _PATH)
plugin = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(plugin)


class ValidIp(unittest.TestCase):
    def test_accepts_addresses(self):
        self.assertTrue(plugin.valid_ip("192.0.2.53", 4))
        self.assertTrue(plugin.valid_ip("2001:db8::53", 6))
        self.assertTrue(plugin.valid_ip("192.0.2.53"))

    def test_rejects_wrong_family_prefix_and_junk(self):
        self.assertFalse(plugin.valid_ip("192.0.2.53", 6))
        self.assertFalse(plugin.valid_ip("2001:db8::53", 4))
        self.assertFalse(plugin.valid_ip("192.0.2.0/24", 4))
        self.assertFalse(plugin.valid_ip("not-an-ip"))
        self.assertFalse(plugin.valid_ip(None))


class ValidNetwork(unittest.TestCase):
    def test_accepts_addresses_and_networks(self):
        self.assertTrue(plugin.valid_network("192.0.2.0/24", 4))
        self.assertTrue(plugin.valid_network("192.0.2.7", 4))
        self.assertTrue(plugin.valid_network("2001:db8::/48", 6))

    def test_rejects_wrong_family_and_junk(self):
        self.assertFalse(plugin.valid_network("2001:db8::/48", 4))
        self.assertFalse(plugin.valid_network("192.0.2.0/33"))
        self.assertFalse(plugin.valid_network(["192.0.2.0/24"]))


class ValidHostname(unittest.TestCase):
    def test_accepts_names(self):
        self.assertTrue(plugin.valid_hostname("dns1.example.net"))
        self.assertTrue(plugin.valid_hostname("DNS1.Example.NET."))

    def test_rejects_bad_names(self):
        self.assertFalse(plugin.valid_hostname("localhost"))
        self.assertFalse(plugin.valid_hostname("-bad.example.net"))
        self.assertFalse(plugin.valid_hostname("bad_.example.net"))
        self.assertFalse(plugin.valid_hostname("a" * 64 + ".example.net"))
        self.assertFalse(plugin.valid_hostname(""))


if __name__ == "__main__":
    unittest.main()
