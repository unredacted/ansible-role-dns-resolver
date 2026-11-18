#!/usr/bin/python3
"""Ask a DNS-over-TLS server one question and print the answer as JSON.

Usage: dns-resolver-query.py <address> <port> <name> [options]

Options:
  --sni NAME        TLS server name to send (and to check, with --cafile)
  --cafile FILE     verify the certificate chain and NAME against this bundle
  --system-ca       verify against the system's trusted CAs
  --dnssec          set the DO bit (ask for DNSSEC data)
  --no-ad           clear the AD bit in the query (it is set by default)
  --timeout SEC     default 5

Prints {"rcode": "NOERROR", "ad": true, "answers": 1, "tls_version": "TLSv1.3"}
and exits 0 if the server answered; exits 1 on any error. Uses Python's ssl
module (OpenSSL), so it works with certificates that carry their names only in
the SAN extension.
"""

import argparse
import json
import os
import socket
import ssl
import struct
import sys

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def build_query(name, dnssec=False, ad=True, qtype=1):
    flags = 0x0100 | (0x0020 if ad else 0)  # RD, and AD unless asked not to
    header = struct.pack(">HHHHHH", int.from_bytes(os.urandom(2), "big"), flags, 1, 0, 0, 1)
    labels = [label for label in name.rstrip(".").split(".") if label]
    qname = b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    opt = b"\x00" + struct.pack(">HHIH", 41, 1232, 0x8000 if dnssec else 0, 0)
    return header + question + opt


def parse_header(message):
    if len(message) < 12:
        raise ValueError("short DNS answer")
    flags, _, ancount = struct.unpack(">HHH", message[2:8])
    return {
        "rcode": RCODES.get(flags & 0x000F, str(flags & 0x000F)),
        "ad": bool(flags & 0x0020),
        "answers": ancount,
    }


def tls_context(cafile, system_ca, sni):
    if cafile or system_ca:
        context = ssl.create_default_context(cafile=cafile or None)
        context.check_hostname = bool(sni)
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["dot"])
    return context


def ask(address, port, name, sni=None, cafile=None, system_ca=False, dnssec=False, ad=True,
        timeout=5.0):
    context = tls_context(cafile, system_ca, sni)
    with socket.create_connection((address, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as tls:
            query = build_query(name, dnssec=dnssec, ad=ad)
            tls.sendall(struct.pack(">H", len(query)) + query)
            length = struct.unpack(">H", read_exact(tls, 2))[0]
            result = parse_header(read_exact(tls, length))
            result["tls_version"] = tls.version()
            return result


def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def main(argv):
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("address")
    parser.add_argument("port", type=int)
    parser.add_argument("name")
    parser.add_argument("--sni")
    parser.add_argument("--cafile")
    parser.add_argument("--system-ca", action="store_true")
    parser.add_argument("--dnssec", action="store_true")
    parser.add_argument("--no-ad", action="store_true")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        result = ask(args.address, args.port, args.name, sni=args.sni, cafile=args.cafile,
                     system_ca=args.system_ca, dnssec=args.dnssec, ad=not args.no_ad,
                     timeout=args.timeout)
    except (OSError, ValueError, ssl.SSLError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
