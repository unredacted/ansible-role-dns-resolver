"""Send one DNS-over-HTTPS query with curl and print a short JSON summary.

Usage: doh_query.py <host> <address> <name> <GET|POST> <ca-file>

Uses only the standard library and the curl binary, so it runs in the test
container without extra packages. Prints {"http_code", "http_version",
"rcode", "answers", "ad"}.
"""

import base64
import json
import struct
import subprocess
import sys
import tempfile


def query(name):
    header = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 1)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".") if label)
    question = qname + b"\x00" + struct.pack(">HH", 1, 1)
    # EDNS OPT record with the DO bit, so the AD bit is meaningful.
    opt = b"\x00" + struct.pack(">HHIH", 41, 1232, 0x8000, 0)
    return header + question + opt


def main(host, address, name, method, ca_file):
    wire = query(name)
    url = f"https://{host}/dns-query"
    target = f"[{address}]" if ":" in address else address
    with tempfile.NamedTemporaryFile() as out:
        cmd = [
            "curl", "-s", "--http2", "--max-time", "10",
            "--cacert", ca_file,
            "--resolve", f"{host}:443:{target}",
            "-o", out.name, "-w", "%{http_code} %{http_version}",
            "-H", "accept: application/dns-message",
        ]
        if method == "GET":
            encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
            cmd += [f"{url}?dns={encoded}"]
        else:
            cmd += ["-H", "content-type: application/dns-message", "--data-binary", "@-", url]
        result = subprocess.run(cmd, input=wire, capture_output=True, check=False)
        code, _, version = result.stdout.decode().partition(" ")
        body = open(out.name, "rb").read()
    summary = {"http_code": code, "http_version": version, "rcode": None, "answers": 0, "ad": False}
    if code == "200" and len(body) >= 12:
        flags = struct.unpack(">H", body[2:4])[0]
        summary.update(rcode=flags & 0xF, answers=struct.unpack(">H", body[6:8])[0],
                       ad=bool(flags & 0x0020))
    print(json.dumps(summary))


if __name__ == "__main__":
    main(*sys.argv[1:6])
