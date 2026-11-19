import importlib.util
import pathlib
import unittest
from unittest import mock

_PATH = pathlib.Path(__file__).resolve().parents[2] / "files" / "acme-hooks" / "cloudflare.py"
_SPEC = importlib.util.spec_from_file_location("cloudflare_hook", _PATH)
hook = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(hook)


class FakeCloudflare:
    """Answers the calls the hook makes, for one zone."""

    def __init__(self, zone="acme.example.net", records=None):
        self.zone = zone
        self.records = records or []
        self.calls = []

    def __call__(self, method, path, token, params=None, body=None):
        self.calls.append((method, path, params, body))
        if method == "GET" and path == "/zones":
            return [{"id": "z1", "name": self.zone}] if params["name"] == self.zone else []
        if method == "GET" and path == "/zones/z1/dns_records":
            return [r for r in self.records
                    if r["name"] == params["name"] and r["content"] == params["content"]]
        if method == "POST":
            self.records.append({"id": f"r{len(self.records)}", **body})
            return body
        if method == "DELETE":
            self.records = [r for r in self.records if r["id"] != path.rsplit("/", 1)[1]]
            return {}
        raise AssertionError(f"unexpected call {method} {path}")


NAME = "dns1-example-org.acme.example.net."


class CloudflareHook(unittest.TestCase):
    def run_hook(self, fake, *argv, token="t0ken"):
        env = {"CF_DNS_API_TOKEN": token}
        with mock.patch.object(hook, "call", fake), mock.patch.dict(hook.os.environ, env):
            return hook.main(list(argv))

    def test_present_finds_the_zone_and_adds_one_record(self):
        fake = FakeCloudflare()
        self.assertEqual(self.run_hook(fake, "present", NAME, "abc"), 0)
        self.assertEqual(fake.records, [{"id": "r0", "type": "TXT", "name": NAME.rstrip("."),
                                         "content": "abc", "ttl": 60}])
        looked_up = [c[2]["name"] for c in fake.calls if c[1] == "/zones"]
        self.assertEqual(looked_up, ["dns1-example-org.acme.example.net", "acme.example.net"])

    def test_present_twice_does_not_duplicate(self):
        fake = FakeCloudflare()
        self.run_hook(fake, "present", NAME, "abc")
        self.run_hook(fake, "present", NAME, "abc")
        self.assertEqual(len(fake.records), 1)

    def test_cleanup_removes_only_the_matching_record(self):
        other = {"id": "keep", "type": "TXT", "name": NAME.rstrip("."), "content": "other"}
        fake = FakeCloudflare(records=[other])
        self.run_hook(fake, "present", NAME, "abc")
        self.assertEqual(self.run_hook(fake, "cleanup", NAME, "abc"), 0)
        self.assertEqual(fake.records, [other])

    def test_no_visible_zone_fails(self):
        fake = FakeCloudflare(zone="elsewhere.example.com")
        self.assertEqual(self.run_hook(fake, "present", NAME, "abc"), 1)

    def test_api_errors_fail_without_printing_the_token(self):
        def failing(*args, **kwargs):
            raise hook.HookError("GET /zones: Invalid access token")
        with mock.patch("sys.stderr") as stderr:
            self.assertEqual(self.run_hook(failing, "present", NAME, "abc", token="s3cret"), 1)
        written = "".join(c.args[0] for c in stderr.write.call_args_list)
        self.assertIn("Invalid access token", written)
        self.assertNotIn("s3cret", written)

    def test_missing_token_and_bad_usage(self):
        with mock.patch.dict(hook.os.environ, {}, clear=True):
            self.assertEqual(hook.main(["present", NAME, "abc"]), 2)
        self.assertEqual(hook.main(["delete", NAME, "abc"]), 2)


if __name__ == "__main__":
    unittest.main()
