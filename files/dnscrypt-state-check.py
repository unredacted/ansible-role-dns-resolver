#!/usr/bin/python3
"""Guard encrypted-dns's provider identity.

encrypted-dns keeps its DNSCrypt provider key in a TOML state file. If it cannot
load that file, it quietly creates a new key, and every published stamp stops
working. This script runs around each start of the service:

  pre     Before start. In published mode the state must exist, parse, be
          readable only by its owner, and hold the pinned public key. Then a
          copy is saved as <state>.prestart.
  post    After start. If the public key changed (the service made a new one),
          put the pre-start copy back, report it, and exit non-zero so systemd
          stops the service.
  verify  From a timer. Same checks as "pre", without copying.

In provisioning mode (no pinned key yet) a missing state is allowed, and "post"
records the public key in <state dir>/provider.pub so the role can print it.

Results go to <textfile dir>/dns_resolver_dnscrypt.prom for node_exporter.

Usage: dnscrypt-state-check.py <pre|post|verify> <state file> <pinned hex key or "-">
                               <textfile dir or "-">
"""

import os
import shutil
import stat
import sys
import time
import tomllib

PUBLIC_KEY_BYTES = 32
SECRET_KEY_BYTES = 64


class StateError(Exception):
    pass


def read_public_key(path):
    """Return the provider public key in hex, checking the file's shape."""
    try:
        with open(path, "rb") as handle:
            state = tomllib.load(handle)
    except FileNotFoundError:
        raise StateError(f"{path} does not exist") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise StateError(f"{path} is not valid TOML: {exc}") from None

    keypair = state.get("provider_kp")
    if not isinstance(keypair, dict):
        raise StateError(f"{path} has no provider_kp table")
    public = keypair.get("pk")
    secret = keypair.get("sk")
    if not (isinstance(public, list) and len(public) == PUBLIC_KEY_BYTES):
        raise StateError(f"{path}: provider_kp.pk is not {PUBLIC_KEY_BYTES} bytes")
    if not (isinstance(secret, list) and len(secret) == SECRET_KEY_BYTES):
        raise StateError(f"{path}: provider_kp.sk is not {SECRET_KEY_BYTES} bytes")
    try:
        public = bytes(public)
        secret = bytes(secret)
    except (TypeError, ValueError):
        raise StateError(f"{path}: the provider key is not a list of bytes") from None
    # libsodium Ed25519 secret keys end with the public key.
    if secret[32:] != public:
        raise StateError(f"{path}: the secret key does not match the public key")
    if not state.get("dnscrypt_encryption_params_set"):
        raise StateError(f"{path} holds no resolver certificates")
    return public.hex()


def check_mode(path):
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise StateError(f"{path} has mode {mode:04o}; it must be readable by its owner only")


def same_owner_as(path, reference):
    """Give path the owner of reference; this script runs as root."""
    info = os.stat(reference)
    os.chown(path, info.st_uid, info.st_gid)


def write_metrics(textfile_dir, values):
    if textfile_dir == "-" or not os.path.isdir(textfile_dir):
        return
    target = os.path.join(textfile_dir, "dns_resolver_dnscrypt.prom")
    lines = [
        "# HELP dns_resolver_dnscrypt_identity_ok 1 if the DNSCrypt state holds the pinned key.",
        "# TYPE dns_resolver_dnscrypt_identity_ok gauge",
        "# HELP dns_resolver_dnscrypt_identity_restored 1 if a new key was undone.",
        "# TYPE dns_resolver_dnscrypt_identity_restored gauge",
        "# HELP dns_resolver_dnscrypt_check_timestamp_seconds Time of the last check.",
        "# TYPE dns_resolver_dnscrypt_check_timestamp_seconds gauge",
    ]
    for name, value in values.items():
        lines.append(f"dns_resolver_dnscrypt_{name} {value}")
    lines.append(f"dns_resolver_dnscrypt_check_timestamp_seconds {int(time.time())}")
    tmp = target + ".tmp"
    with open(tmp, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, target)


def main(action, state_path, pinned, textfile_dir):
    pinned = "" if pinned == "-" else pinned.lower()
    published = bool(pinned)
    prestart = state_path + ".prestart"

    if action in ("pre", "verify"):
        if not published and not os.path.exists(state_path):
            print("Provisioning mode: no state yet; encrypted-dns will create a provider key.")
            return 0
        try:
            public = read_public_key(state_path)
            check_mode(state_path)
            if published and public != pinned:
                raise StateError(f"the provider key is {public}, but {pinned} is pinned")
        except StateError as exc:
            write_metrics(textfile_dir, {"identity_ok": 0})
            print(f"DNSCrypt state check failed: {exc}", file=sys.stderr)
            return 1
        if action == "pre":
            shutil.copy2(state_path, prestart)
            os.chmod(prestart, 0o600)
            same_owner_as(prestart, state_path)
        write_metrics(textfile_dir, {"identity_ok": 1, "identity_restored": 0})
        return 0

    if action == "post":
        # encrypted-dns loads or creates its state before it starts listening.
        time.sleep(3)
        try:
            public = read_public_key(state_path)
        except StateError as exc:
            print(f"DNSCrypt state unreadable after start: {exc}", file=sys.stderr)
            public = None
        if not published:
            if public:
                record = os.path.join(os.path.dirname(state_path), "provider.pub")
                with open(record, "w") as handle:
                    handle.write(public + "\n")
            return 0
        if public == pinned:
            return 0
        if os.path.exists(prestart):
            os.replace(prestart, state_path)
            os.chmod(state_path, 0o600)
            same_owner_as(state_path, os.path.dirname(state_path))
        write_metrics(textfile_dir, {"identity_ok": 0, "identity_restored": 1})
        print(
            f"encrypted-dns replaced its provider key ({public}); the saved state was put back. "
            "Find out why it could not read the state file before starting it again.",
            file=sys.stderr,
        )
        return 1

    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:5]))
