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


class Stamps(unittest.TestCase):
    def test_dnscrypt_stamp_matches_what_encrypted_dns_prints(self):
        # Printed by encrypted-dns 0.9.22 for this provider and address.
        expected = (
            "sdns://AQcAAAAAAAAADzE5Mi4wLjIuNTM6ODQ0MyB5zrBtf_edTYYTe_rwBHa6nIhQJKKhm8wjcZM297cKqCAy"
            "LmRuc2NyeXB0LWNlcnQuZG5zMS5leGFtcGxlLm5ldA"
        )
        stamp = plugin.dns_stamp(
            "dnscrypt", "192.0.2.53", 8443,
            provider_pubkey="79ceb06d7ff79d4d86137bfaf00476ba9c885024a2a19bcc23719336f7b70aa8",
            provider_name="2.dnscrypt-cert.dns1.example.net",
        )
        self.assertEqual(stamp, expected)

    def test_doh_stamp_matches_a_published_one(self):
        # The DoH stamp published for 1.0.0.1 / dns.cloudflare.com.
        expected = "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5"
        stamp = plugin.dns_stamp("doh", "1.0.0.1", 443, hostname="dns.cloudflare.com")
        self.assertEqual(stamp, expected)

    def test_ipv6_and_non_default_ports_are_written_out(self):
        stamp = plugin.dns_stamp("dot", "2001:db8::53", 8853, hostname="dns1.example.net")
        raw = __import__("base64").urlsafe_b64decode(stamp[7:] + "==")
        self.assertEqual(raw[0], 0x03)
        self.assertIn(b"[2001:db8::53]:8853", raw)
