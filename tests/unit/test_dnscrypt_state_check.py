import importlib.util
import os
import pathlib
import socket
import tempfile
import threading
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
        self.guard = os.path.join(self.dir.name, "guard")

    def run_check(self, action, pinned, metrics="-"):
        return check.main(action, self.state, pinned, metrics, guard_dir=self.guard)

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
        self.assertEqual(self.run_check("pre", KEY_A.hex(), self.metrics), 0)
        self.assertTrue(os.path.exists(os.path.join(self.guard, "state.prestart")))
        self.assertEqual(self.metric("identity_ok"), 1)

    def test_pre_refuses_another_key(self):
        self.write(state_text(KEY_B))
        self.assertEqual(self.run_check("pre", KEY_A.hex(), self.metrics), 1)
        self.assertEqual(self.metric("identity_ok"), 0)

    def test_pre_refuses_a_missing_state_when_published(self):
        self.assertEqual(self.run_check("pre", KEY_A.hex()), 1)

    def test_pre_allows_a_missing_state_while_provisioning(self):
        self.assertEqual(self.run_check("pre", "-"), 0)

    def test_pre_refuses_invalid_toml(self):
        self.write("[provider_kp\n")
        self.assertEqual(self.run_check("pre", KEY_A.hex()), 1)

    def test_pre_refuses_valid_toml_without_certificates(self):
        self.write(state_text(KEY_A, with_certs=False))
        self.assertEqual(self.run_check("pre", KEY_A.hex()), 1)

    def test_pre_refuses_a_secret_key_that_does_not_match(self):
        seed = b"\x01" * 32
        good, bad = list(seed + KEY_A), list(seed + KEY_B)
        text = state_text(KEY_A).replace(f"sk = {good}", f"sk = {bad}")
        self.write(text)
        self.assertEqual(self.run_check("pre", KEY_A.hex()), 1)

    def test_pre_refuses_a_state_others_can_read(self):
        self.write(state_text(KEY_A), mode=0o644)
        self.assertEqual(self.run_check("pre", KEY_A.hex()), 1)

    def test_post_puts_back_the_saved_state_when_the_key_changed(self):
        self.write(state_text(KEY_A))
        self.run_check("pre", KEY_A.hex(), self.metrics)
        self.write(state_text(KEY_B))  # what encrypted-dns does on a load error
        with mock.patch.object(check.time, "sleep"):
            self.assertEqual(self.run_check("post", KEY_A.hex(), self.metrics), 1)
        self.assertEqual(check.read_public_key(self.state), KEY_A.hex())
        self.assertEqual(self.metric("identity_restored"), 1)

    def test_post_is_quiet_when_the_key_is_unchanged(self):
        self.write(state_text(KEY_A))
        with mock.patch.object(check.time, "sleep"):
            self.assertEqual(self.run_check("post", KEY_A.hex(), self.metrics), 0)

    def test_post_records_the_key_while_provisioning(self):
        self.write(state_text(KEY_A))
        with mock.patch.object(check.time, "sleep"):
            self.assertEqual(self.run_check("post", "-"), 0)
        record = os.path.join(self.guard, "provider.pub")
        self.assertEqual(open(record).read().strip(), KEY_A.hex())

    def test_pre_refuses_a_state_its_owner_cannot_read(self):
        self.write(state_text(KEY_A), mode=0o200)
        self.assertEqual(self.run_check("pre", KEY_A.hex()), 1)

    def test_access_check_wants_the_state_directory_owner(self):
        owner = os.stat(self.dir.name).st_uid
        info = os.stat_result((0o100600, 0, 0, 1, owner + 1, 0, 0, 0, 0, 0))
        with self.assertRaises(check.StateError):
            check.check_access(self.state, info)

    def test_pre_refuses_a_linked_state(self):
        real = os.path.join(self.dir.name, "elsewhere")
        with open(real, "w") as handle:
            handle.write(state_text(KEY_A))
        os.chmod(real, 0o600)
        os.symlink(real, self.state)
        self.assertEqual(self.run_check("pre", KEY_A.hex()), 1)

    def test_pre_replaces_a_planted_link_instead_of_following_it(self):
        victim = os.path.join(self.dir.name, "victim")
        with open(victim, "w") as handle:
            handle.write("keep me\n")
        os.makedirs(self.guard, mode=0o700)
        os.symlink(victim, os.path.join(self.guard, "state.prestart"))
        self.write(state_text(KEY_A))
        self.assertEqual(self.run_check("pre", KEY_A.hex()), 0)
        self.assertEqual(open(victim).read(), "keep me\n")
        self.assertFalse(os.path.islink(os.path.join(self.guard, "state.prestart")))

    def test_the_restored_alert_stays_until_cleared(self):
        self.write(state_text(KEY_A))
        self.run_check("pre", KEY_A.hex(), self.metrics)
        self.write(state_text(KEY_B))
        self.assertEqual(self.run_check("post", KEY_A.hex(), self.metrics), 1)
        self.assertEqual(self.run_check("pre", KEY_A.hex(), self.metrics), 0)
        self.assertEqual(self.metric("identity_ok"), 1)
        self.assertEqual(self.metric("identity_restored"), 1)
        os.remove(os.path.join(self.guard, "identity-restored"))
        self.run_check("pre", KEY_A.hex(), self.metrics)
        self.assertEqual(self.metric("identity_restored"), 0)

    def test_post_waits_for_an_answer_before_reading_the_key(self):
        self.write(state_text(KEY_A))
        calls = []

        def serving(*args):
            calls.append(args)
            return True

        with mock.patch.object(check, "wait_until_serving", serving):
            result = check.main("post", self.state, KEY_A.hex(), "-", guard_dir=self.guard,
                                probe=["192.0.2.53", "8443", "2.dnscrypt-cert.example.net"])
        self.assertEqual(result, 0)
        self.assertEqual(calls, [("192.0.2.53", "8443", "2.dnscrypt-cert.example.net")])

    def test_post_fails_when_the_service_never_answers(self):
        self.write(state_text(KEY_A))
        with mock.patch.object(check, "wait_until_serving", return_value=False):
            result = check.main("post", self.state, KEY_A.hex(), "-", guard_dir=self.guard,
                                probe=["192.0.2.53", "8443", "2.dnscrypt-cert.example.net"])
        self.assertEqual(result, 1)


class Probe(unittest.TestCase):
    def test_waits_for_a_matching_answer(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def answer():
            data, peer = server.recvfrom(512)
            server.sendto(data[:2] + b"\x80\x00" + data[4:], peer)

        thread = threading.Thread(target=answer)
        thread.start()
        try:
            self.assertTrue(check.wait_until_serving("127.0.0.1", port, "2.dnscrypt-cert.x.net", 5))
        finally:
            thread.join()
            server.close()

    def test_gives_up_without_an_answer(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as quiet:
            quiet.bind(("127.0.0.1", 0))
            port = quiet.getsockname()[1]
            answered = check.wait_until_serving("127.0.0.1", port, "2.dnscrypt-cert.x.net", 2)
            self.assertFalse(answered)


if __name__ == "__main__":
    unittest.main()
