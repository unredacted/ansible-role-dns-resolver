"""Fetch a DNSCrypt server's certificates and print their versions as JSON.

Usage: dnscrypt_certs.py <address> <port> <provider name> <udp|tcp>

The certificates are TXT records for the provider name, answered over plain
DNS on the DNSCrypt port. Each one starts with "DNSC" and a 2-byte version:
2 is the classic X25519 construction, 3 is post-quantum (X-Wing).

Over UDP the server may not answer with more than it was sent, so the large
post-quantum certificate is left out and the TC bit is set; over TCP every
certificate is sent. Prints {"versions": [...], "truncated": bool}.
"""

import json
import socket
import struct
import sys


def query(name):
    header = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".") if label)
    return header + qname + b"\x00" + struct.pack(">HH", 16, 1)


def skip_name(data, offset):
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def ask(address, port, provider, transport):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    if transport == "udp":
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(query(provider), (address, int(port)))
        return sock.recvfrom(65535)[0]
    sock = socket.create_connection((address, int(port)), timeout=5)
    message = query(provider)
    sock.sendall(struct.pack(">H", len(message)) + message)
    length = struct.unpack(">H", sock.recv(2, socket.MSG_WAITALL))[0]
    return sock.recv(length, socket.MSG_WAITALL)


def main(address, port, provider, transport):
    data = ask(address, port, provider, transport)
    truncated = bool(data[2] & 0x02)
    answers = struct.unpack(">H", data[6:8])[0]
    offset = skip_name(data, 12) + 4
    versions = []
    for _ in range(answers):
        offset = skip_name(data, offset)
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype != 16:
            continue
        blob, i = b"", 0
        while i < len(rdata):
            blob += rdata[i + 1:i + 1 + rdata[i]]
            i += 1 + rdata[i]
        if blob[:4] == b"DNSC":
            versions.append(struct.unpack(">H", blob[4:6])[0])
    print(json.dumps({"versions": sorted(versions), "truncated": truncated}))


if __name__ == "__main__":
    main(*sys.argv[1:5])
