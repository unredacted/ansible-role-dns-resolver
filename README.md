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
| `dns_resolver_mgmt_interface` | `""` | Interface for SSH and metrics. Empty means any interface. |
| `dns_resolver_mgmt_tcp_ports` | `[22]` | SSH and other management TCP ports. |
| `dns_resolver_mgmt_udp_ports` | `[]` | UDP ports to accept from anywhere, such as a VPN port. |
| `dns_resolver_metrics_listen` | `127.0.0.1` | Address of the metrics endpoints. |
| `dns_resolver_metrics_allowed_sources_v4` / `_v6` | `[]` | Who may scrape metrics. |
| `dns_resolver_meter_pps` / `_burst` | `300` / `600` | Packets per second per source (IPv6 per /64). |
| `dns_resolver_conn_cap_per_source` | `32` | Open connections per source. |
| `dns_resolver_tls_source` | `files` | Where the certificate comes from. |
| `dns_resolver_tls_cert_src` / `_key_src` | `""` | Chain and key on the controller (`files` source). |
| `dns_resolver_qname_minimization` | `Relaxed` | `Strict` or `Relaxed`. |
| `dns_resolver_deny_servers_extra` | `[]` | More networks Hickory must never query. |
| `dns_resolver_trust_anchor_required_tags` | `[38696]` | Root key tags the trust anchor file must contain. |
| `dns_resolver_hickory_memory_max` | `2G` | Memory limit for Hickory. |
| `dns_resolver_allow_disk_swap` | `false` | Allow running with swap on disk. |
| `dns_resolver_binary_release` and the URL and SHA-256 variables | set by CI | The pinned binary release. |

## Binaries

The role installs prebuilt binaries from this repository's GitHub releases.
Each release has a tag like `binaries-20261117-abc1234`, and its assets are
never replaced. `defaults/main.yml` pins one release, with a SHA-256 sum for
each binary.

How a release is made:

- `build/run.sh` builds both programs in a digest-pinned Debian 13 Rust
  image, for `x86_64-unknown-linux-gnu`.
- hickory-dns is built from `build/hickory-dns/`, a small wrapper crate with
  its own `Cargo.lock`. Its `src/main.rs` is an unmodified copy of upstream's
  entrypoint, and CI checks that it still matches. The wrapper exists so that
  Dependabot can propose dependency updates.
- encrypted-dns is built from the crates.io package, using the lockfile that
  ships with it. The version and the package checksum are in
  `build/versions.yml`.
- The build runs `cargo deny` and `cargo audit`, and fails if `ring` is in
  the hickory-dns dependency tree. aws-lc-rs is its only TLS crypto provider,
  because ring has no post-quantum key exchange.
- Each release includes SBOMs, `SHA256SUMS`, a list of the native (C) code in
  the binaries, and a GitHub build provenance attestation. Check a download
  with `gh attestation verify hickory-dns --repo unredacted/ansible-role-dns-resolver`.
- After a release, CI opens a pull request that points `defaults/main.yml` at
  it.

Updates:

- Dependabot proposes new versions of the builder image and of the Rust crates
  behind hickory-dns.
- A weekly workflow opens a pull request when encrypted-dns has a new release.
- A weekly workflow audits the newest release and opens an issue if it finds
  an advisory.

To update hickory-dns itself, change the version in
`build/hickory-dns/Cargo.toml` and `build/versions.yml`, and copy upstream's
`bin/src/hickory-dns.rs` for that version into `build/hickory-dns/src/main.rs`.

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
- Hickory logs query names at warning level on some errors, so the role turns
  off logging for its request-handling modules. What is left goes to a journal
  namespace kept in memory. Core dumps are not stored, and swap is turned off
  for the DNS programs.
- The metrics endpoints carry only totals, never names or addresses.
- Encryption covers the connection between the client and this resolver. To
  find answers, the resolver asks other DNS servers from its own address,
  without encryption, and sends only as much of the name as each step needs.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
