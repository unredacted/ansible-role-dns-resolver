import importlib.util
import pathlib
import struct
import unittest

_PATH = pathlib.Path(__file__).resolve().parents[2] / "files" / "dns-resolver-query.py"
_SPEC = importlib.util.spec_from_file_location("dns_resolver_query", _PATH)
query = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(query)


class BuildQuery(unittest.TestCase):
    def test_flags_and_opt_record(self):
        wire = query.build_query("ietf.org", dnssec=True, ad=True)
        flags = struct.unpack(">H", wire[2:4])[0]
        self.assertTrue(flags & 0x0100)  # RD
        self.assertTrue(flags & 0x0020)  # AD
        self.assertIn(b"\x04ietf\x03org\x00", wire)
        # The OPT record's TTL field carries the DO bit.
        self.assertEqual(wire[-6:-2], struct.pack(">I", 0x8000))

    def test_plain_query_has_no_ad_and_no_do(self):
        wire = query.build_query("example.com.", dnssec=False, ad=False)
        flags = struct.unpack(">H", wire[2:4])[0]
        self.assertFalse(flags & 0x0020)
        self.assertEqual(wire[-6:-2], struct.pack(">I", 0))


class ParseHeader(unittest.TestCase):
    def test_reads_rcode_ad_and_answer_count(self):
        header = struct.pack(">HHHHHH", 1, 0x8000 | 0x0100 | 0x0080 | 0x0020 | 3, 1, 0, 0, 0)
        expected = {"rcode": "NXDOMAIN", "ad": True, "answers": 0}
        self.assertEqual(query.parse_header(header), expected)

    def test_rejects_short_answers(self):
        with self.assertRaises(ValueError):
            query.parse_header(b"\x00" * 5)


if __name__ == "__main__":
    unittest.main()
