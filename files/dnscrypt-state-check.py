#!/usr/bin/python3
"""Guard encrypted-dns's provider identity.

encrypted-dns keeps its DNSCrypt provider key in a TOML state file. If it cannot
load that file, it quietly creates a new key, and every published stamp stops
working. This script runs as root around each start of the service:

  pre     Before start. In published mode the state must exist, parse, be a
          regular file owned by the state directory's owner and readable only
          by that owner, and hold the pinned public key. Then a copy is saved
          in the guard directory.
  post    After start. Waits until encrypted-dns answers a certificate query
          (it loads or replaces its state before it answers), then reads the
          key. If the key changed, it puts the saved copy back, raises the
          alert, and exits non-zero so systemd stops the service.
  verify  From a timer or the role. Same checks as "pre", without copying.

The guard directory belongs to root, so the service account cannot plant
links there. Files the script writes are created new (never through an
existing name) and renamed into place.

In provisioning mode (no pinned key yet) a missing state is allowed, and "post"
records the public key in <guard dir>/provider.pub so the role can print it.

When a key is put back, <guard dir>/identity-restored is created and the
dns_resolver_dnscrypt_identity_restored metric stays 1 until an operator
removes that file.

Results go to <textfile dir>/dns_resolver_dnscrypt.prom for node_exporter.

Usage: dnscrypt-state-check.py <pre|post|verify> <state file> <pinned hex key or "-">
                               <textfile dir or "-"> [--guard-dir DIR]
                               [--probe ADDRESS PORT PROVIDER_NAME]
"""

import argparse
import os
import secrets
import socket
import stat
import struct
import sys
import time
import tomllib

PUBLIC_KEY_BYTES = 32
SECRET_KEY_BYTES = 64
GUARD_DIR = "/var/lib/dns-resolver/dnscrypt"
PRESTART = "state.prestart"
RESTORED = "identity-restored"
PROBE_SECONDS = 30


class StateError(Exception):
    pass


def read_regular(path):
    """Read a regular file without following a link. Returns (bytes, stat)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        raise StateError(f"{path} does not exist") from None
    except OSError as exc:
        raise StateError(f"{path} cannot be opened: {exc.strerror}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise StateError(f"{path} is not a regular file")
        chunks = []
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
        return b"".join(chunks), info
    finally:
        os.close(fd)


def parse_public_key(data, path):
    """Return the provider public key in hex, checking the state's shape."""
    try:
        state = tomllib.loads(data.decode())
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


def read_public_key(path):
    return parse_public_key(read_regular(path)[0], path)


def check_access(path, info):
    """The service account must own the state and be the only one to read it."""
    owner = os.stat(os.path.dirname(path) or ".").st_uid
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        raise StateError(f"{path} has mode {mode:04o}; it must be readable by its owner only")
    if not mode & 0o400:
        raise StateError(f"{path} has mode {mode:04o}; its owner cannot read it")
    if info.st_uid != owner:
        raise StateError(
            f"{path} is owned by uid {info.st_uid}, not by the state directory's owner ({owner})"
        )


def write_new(directory, name, data, mode, uid=None, gid=None):
    """Write directory/name by creating a fresh file and renaming it into place.

    The temporary file is created with O_EXCL and O_NOFOLLOW, and the rename
    replaces whatever is at the name (a link included) without following it.
    """
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        tmp = f".{name}.{secrets.token_hex(8)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(tmp, flags, 0o600, dir_fd=dir_fd)
        try:
            if uid is not None:
                os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


def prepare_guard_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise StateError(f"{path} must be a directory that only its owner (root) can write")


def restored_since(guard_dir):
    """Time of the last put-back, or None."""
    try:
        data, _ = read_regular(os.path.join(guard_dir, RESTORED))
        return int(data.split()[0])
    except (StateError, ValueError, IndexError):
        return None


def write_metrics(textfile_dir, guard_dir, identity_ok):
    if textfile_dir == "-" or not os.path.isdir(textfile_dir):
        return
    since = restored_since(guard_dir)
    lines = [
        "# HELP dns_resolver_dnscrypt_identity_ok 1 if the DNSCrypt state holds the pinned key.",
        "# TYPE dns_resolver_dnscrypt_identity_ok gauge",
        f"dns_resolver_dnscrypt_identity_ok {identity_ok}",
        "# HELP dns_resolver_dnscrypt_identity_restored 1 after a new key was undone, until "
        "the identity-restored file is removed.",
        "# TYPE dns_resolver_dnscrypt_identity_restored gauge",
        f"dns_resolver_dnscrypt_identity_restored {0 if since is None else 1}",
    ]
    if since is not None:
        lines += [
            "# HELP dns_resolver_dnscrypt_identity_restored_timestamp_seconds "
            "Time of the last put-back.",
            "# TYPE dns_resolver_dnscrypt_identity_restored_timestamp_seconds gauge",
            f"dns_resolver_dnscrypt_identity_restored_timestamp_seconds {since}",
        ]
    lines += [
        "# HELP dns_resolver_dnscrypt_check_timestamp_seconds Time of the last check.",
        "# TYPE dns_resolver_dnscrypt_check_timestamp_seconds gauge",
        f"dns_resolver_dnscrypt_check_timestamp_seconds {int(time.time())}",
    ]
    body = ("\n".join(lines) + "\n").encode()
    write_new(textfile_dir, "dns_resolver_dnscrypt.prom", body, 0o644)


def certificate_query(name):
    labels = [label for label in name.rstrip(".").split(".") if label]
    qname = b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\x00"
    query_id = secrets.randbits(16)
    header = struct.pack(">HHHHHH", query_id, 0, 1, 0, 0, 0)
    return query_id, header + qname + struct.pack(">HH", 16, 1)  # TXT, IN


def wait_until_serving(address, port, provider_name, seconds=PROBE_SECONDS):
    """True once encrypted-dns answers a certificate query over UDP."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        query_id, query = certificate_query(provider_name)
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.0)
            try:
                sock.sendto(query, (address, int(port)))
                reply, _ = sock.recvfrom(4096)
                if len(reply) >= 2 and struct.unpack(">H", reply[:2])[0] == query_id:
                    return True
            except OSError:
                pass
        time.sleep(0.5)
    return False


def main(action, state_path, pinned, textfile_dir, guard_dir=GUARD_DIR, probe=None):
    pinned = "" if pinned == "-" else pinned.lower()
    published = bool(pinned)
    state_dir = os.path.dirname(state_path) or "."
    state_name = os.path.basename(state_path)

    try:
        prepare_guard_dir(guard_dir)
    except (OSError, StateError) as exc:
        print(f"DNSCrypt guard directory problem: {exc}", file=sys.stderr)
        return 1

    if action in ("pre", "verify"):
        if not published and not os.path.lexists(state_path):
            print("Provisioning mode: no state yet; encrypted-dns will create a provider key.")
            return 0
        try:
            data, info = read_regular(state_path)
            public = parse_public_key(data, state_path)
            check_access(state_path, info)
            if published and public != pinned:
                raise StateError(f"the provider key is {public}, but {pinned} is pinned")
        except StateError as exc:
            write_metrics(textfile_dir, guard_dir, 0)
            print(f"DNSCrypt state check failed: {exc}", file=sys.stderr)
            return 1
        if action == "pre":
            write_new(guard_dir, PRESTART, data, 0o600)
        write_metrics(textfile_dir, guard_dir, 1)
        return 0

    if action == "post":
        serving = True
        if probe:
            serving = wait_until_serving(*probe)
            if not serving:
                print(f"encrypted-dns did not answer a certificate query within {PROBE_SECONDS}s.",
                      file=sys.stderr)
        try:
            public = read_public_key(state_path)
        except StateError as exc:
            print(f"DNSCrypt state unreadable after start: {exc}", file=sys.stderr)
            public = None
        if not published:
            if public:
                write_new(guard_dir, "provider.pub", (public + "\n").encode(), 0o644)
            return 0 if serving else 1
        if public == pinned:
            return 0 if serving else 1
        try:
            saved, _ = read_regular(os.path.join(guard_dir, PRESTART))
            owner = os.stat(state_dir)
            write_new(state_dir, state_name, saved, 0o600, owner.st_uid, owner.st_gid)
        except StateError as exc:
            print(f"No saved state to put back: {exc}", file=sys.stderr)
        write_new(guard_dir, RESTORED, f"{int(time.time())}\n".encode(), 0o600)
        write_metrics(textfile_dir, guard_dir, 0)
        print(
            f"encrypted-dns replaced its provider key ({public}); the saved state was put back. "
            "Find out why it could not read the state file before starting it again, then "
            f"remove {os.path.join(guard_dir, RESTORED)} to clear the alert.",
            file=sys.stderr,
        )
        return 1

    print(__doc__, file=sys.stderr)
    return 2


def parse_args(argv):
    parser = argparse.ArgumentParser(usage=__doc__.split("Usage: ", 1)[1])
    parser.add_argument("action", choices=["pre", "post", "verify"])
    parser.add_argument("state")
    parser.add_argument("pinned")
    parser.add_argument("textfile_dir")
    parser.add_argument("--guard-dir", default=GUARD_DIR)
    parser.add_argument("--probe", nargs=3, metavar=("ADDRESS", "PORT", "PROVIDER_NAME"))
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    sys.exit(main(args.action, args.state, args.pinned, args.textfile_dir,
                  guard_dir=args.guard_dir, probe=args.probe))
