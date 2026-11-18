import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock

_PATH = pathlib.Path(__file__).resolve().parents[2] / "files" / "dnscrypt-state-check.py"
_SPEC = importlib.util.spec_from_file_location("dnscrypt_state_check", _PATH)
check = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check)


def state_text(public, secret_seed=b"\x01" * 32, with_certs=True):
    """A state file shaped like encrypted-dns 0.9.22 writes it."""
    secret = secret_seed + public
    text = "[provider_kp]\n"
    text += f"sk = {list(secret)}\n"
    text += f"pk = {list(public)}\n"
    if with_certs:
        text += "\n[[dnscrypt_encryption_params_set]]\ndnscrypt_cert = [1, 2, 3]\n"
    return text


KEY_A = bytes(range(32))
KEY_B = bytes(range(1, 33))


class StateCheck(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.dir.name, "encrypted-dns.state")
        self.metrics = os.path.join(self.dir.name, "metrics")
        os.mkdir(self.metrics)

    def tearDown(self):
        self.dir.cleanup()

    def write(self, text, mode=0o600):
        with open(self.state, "w") as handle:
            handle.write(text)
        os.chmod(self.state, mode)

    def metric(self, name):
        path = os.path.join(self.metrics, "dns_resolver_dnscrypt.prom")
        for line in open(path):
            if line.startswith(f"dns_resolver_dnscrypt_{name} "):
                return int(line.split()[1])
        return None

    def test_pre_accepts_the_pinned_key_and_saves_a_copy(self):
        self.write(state_text(KEY_A))
        self.assertEqual(check.main("pre", self.state, KEY_A.hex(), self.metrics), 0)
        self.assertTrue(os.path.exists(self.state + ".prestart"))
        self.assertEqual(self.metric("identity_ok"), 1)

    def test_pre_refuses_another_key(self):
        self.write(state_text(KEY_B))
        self.assertEqual(check.main("pre", self.state, KEY_A.hex(), self.metrics), 1)
        self.assertEqual(self.metric("identity_ok"), 0)

    def test_pre_refuses_a_missing_state_when_published(self):
        self.assertEqual(check.main("pre", self.state, KEY_A.hex(), "-"), 1)

    def test_pre_allows_a_missing_state_while_provisioning(self):
        self.assertEqual(check.main("pre", self.state, "-", "-"), 0)

    def test_pre_refuses_invalid_toml(self):
        self.write("[provider_kp\n")
        self.assertEqual(check.main("pre", self.state, KEY_A.hex(), "-"), 1)

    def test_pre_refuses_valid_toml_without_certificates(self):
        self.write(state_text(KEY_A, with_certs=False))
        self.assertEqual(check.main("pre", self.state, KEY_A.hex(), "-"), 1)

    def test_pre_refuses_a_secret_key_that_does_not_match(self):
        seed = b"\x01" * 32
        good, bad = list(seed + KEY_A), list(seed + KEY_B)
        text = state_text(KEY_A).replace(f"sk = {good}", f"sk = {bad}")
        self.write(text)
        self.assertEqual(check.main("pre", self.state, KEY_A.hex(), "-"), 1)

    def test_pre_refuses_a_state_others_can_read(self):
        self.write(state_text(KEY_A), mode=0o644)
        self.assertEqual(check.main("pre", self.state, KEY_A.hex(), "-"), 1)

    def test_post_puts_back_the_saved_state_when_the_key_changed(self):
        self.write(state_text(KEY_A))
        check.main("pre", self.state, KEY_A.hex(), self.metrics)
        self.write(state_text(KEY_B))  # what encrypted-dns does on a load error
        with mock.patch.object(check.time, "sleep"):
            self.assertEqual(check.main("post", self.state, KEY_A.hex(), self.metrics), 1)
        self.assertEqual(check.read_public_key(self.state), KEY_A.hex())
        self.assertEqual(self.metric("identity_restored"), 1)

    def test_post_is_quiet_when_the_key_is_unchanged(self):
        self.write(state_text(KEY_A))
        with mock.patch.object(check.time, "sleep"):
            self.assertEqual(check.main("post", self.state, KEY_A.hex(), self.metrics), 0)

    def test_post_records_the_key_while_provisioning(self):
        self.write(state_text(KEY_A))
        with mock.patch.object(check.time, "sleep"):
            self.assertEqual(check.main("post", self.state, "-", "-"), 0)
        record = os.path.join(self.dir.name, "provider.pub")
        self.assertEqual(open(record).read().strip(), KEY_A.hex())


if __name__ == "__main__":
    unittest.main()
