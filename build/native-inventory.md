# Native (non-Rust) code in the release binaries

Both programs are written in Rust. They still link some code written in C or
assembly. This list is part of each release, next to the SBOMs.

| Code | Used by | What for |
|---|---|---|
| glibc | both | The C library on Debian 13. Linked dynamically from the host. |
| aws-lc (through `aws-lc-sys`) | hickory-dns | TLS (DoT, DoH, DoQ), post-quantum key exchange (ML-KEM), DNSSEC signature checks. |
| libsodium (through `libsodium-sys-stable`) | encrypted-dns | DNSCrypt encryption and signatures, and the X-Wing post-quantum key exchange. |
| mimalloc | encrypted-dns | Memory allocator. Upstream sets it as the global allocator. |

The hickory-dns build fails if `ring` appears in its dependency graph, so that
aws-lc-rs is its only TLS crypto provider.

Security fixes in these libraries reach us through new upstream crate
versions. We do not patch them ourselves.

About aws-lc: its ML-KEM code comes from the mlkem-native project. That
project's C code has machine-checked proofs (CBMC) that it has no memory or
integer overflows, and its x86_64 and AArch64 assembly has separate proofs in
HOL Light. The rest of aws-lc is conventional C and assembly.
