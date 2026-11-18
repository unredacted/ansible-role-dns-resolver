# ansible-role-dns-resolver

An Ansible role that runs a public DNS resolver which only accepts encrypted
connections.

The DNS software is written in Rust:

- [Hickory DNS](https://github.com/hickory-dns/hickory-dns) looks up names
  (recursive resolution with DNSSEC validation) and answers over DNS-over-TLS,
  DNS-over-QUIC and DNS-over-HTTPS.
- [encrypted-dns-server](https://github.com/DNSCrypt/encrypted-dns-server)
  answers DNSCrypt, including its post-quantum mode, and passes queries to
  Hickory on the same machine.

> Status: under development. Not ready for use yet.

## What it does

- Installs pinned, checksummed builds of both programs.
- Serves DNS-over-TLS (853/tcp), DNS-over-QUIC (853/udp), DNS-over-HTTPS
  (443/tcp, POST only) and DNSCrypt (8443/udp and tcp).
- Prefers post-quantum key exchange (X25519MLKEM768) when the client supports
  it, and falls back to X25519 when it does not.
- Gets TLS certificates from an ACME CA with a DNS challenge.
- Manages its own nftables table with per-source rate limits, and can run in
  a "pilot" mode that only allows listed sources.
- Keeps no query logs. See "Security and privacy notes".

## What it does not do

- Plain DNS on port 53 to the public.
- DNS-over-HTTPS with GET requests, or over HTTP/3. Hickory does not support
  these yet.
- Filtering or blocklists.
- Serving stale answers, a local copy of the root zone, or aggressive NSEC
  caching. Hickory does not support these yet.

## Known issues

These come from the upstream programs. We do not patch them. We pick up fixes
when upstream releases them.

- **DoH GET is refused.** Clients that send POST work. Some browser settings
  use GET and will fail.
- **Some names fail now and then.** Hickory 0.26.3 can return SERVFAIL for a
  few names with chains of unsigned delegations (for example
  `www.blogger.com`). A retry usually works. The fix is merged upstream but not
  released yet.
- **DNSCrypt may give an older answer when the resolver behind it fails.**
  encrypted-dns-server returns its cached copy of a name when Hickory answers
  with an error. That copy was valid when it was cached.
- **DNSCrypt makes a new key if its state file cannot be read.** The role
  checks the key before and after every start, puts the old file back if the
  key changed, and raises an alert.

## Requirements

- Debian 13 (trixie) on x86_64.
- Ansible 2.17 or newer on the controller.
- A DNS provider supported by [lego](https://go-acme.github.io/lego/) for the
  ACME DNS challenge.

## Example playbook

```yaml
- hosts: resolvers
  roles:
    - role: ansible-role-dns-resolver
      vars:
        dns_resolver_hostnames:
          - dns1.example.net
        dns_resolver_listen_v4:
          - 192.0.2.53
        dns_resolver_listen_v6:
          - 2001:db8::53
        dns_resolver_access: pilot
        dns_resolver_pilot_sources_v4:
          - 198.51.100.0/24
```

## Variables

All variables start with `dns_resolver_`. `defaults/main.yml` has a comment
for each one.

| Variable | Default | Meaning |
|---|---|---|
| `dns_resolver_hostnames` | `[]` | Names clients use. All go into the certificate. |
| `dns_resolver_listen_v4` | `[]` | Public IPv4 addresses to listen on. |
| `dns_resolver_listen_v6` | `[]` | Public IPv6 addresses to listen on. |
| `dns_resolver_access` | `pilot` | `pilot` allows only the listed sources. `public` allows everyone. |
| `dns_resolver_pilot_sources_v4` | `[]` | IPv4 sources allowed in pilot mode. |
| `dns_resolver_pilot_sources_v6` | `[]` | IPv6 sources allowed in pilot mode. |

## Testing

```bash
pip install -r requirements-ci.txt
ansible-galaxy collection install -r requirements.yml
yamllint . && ansible-lint && ruff check .
python -m unittest discover -s tests/unit
molecule test
```

Molecule needs Docker. The tests run in a Debian 13 container with systemd.

## Security and privacy notes

- We do not log DNS queries or client IP addresses. The programs keep some
  state in memory to answer queries and limit abuse.
- Encryption covers the connection between the client and this resolver. To
  find answers, the resolver asks other DNS servers from its own address,
  without encryption, and sends only as much of the name as each step needs.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
