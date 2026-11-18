#!/usr/bin/env bash
# Build both binaries inside the builder image. Run from the repository root:
#
#   build/run.sh            (builds the image, then runs this script in it)
#
# Output goes to artifacts/: the binaries, SHA256SUMS, SBOMs and BUILDINFO.
set -euo pipefail

cd /src
out=/src/artifacts
rm -rf "$out"
mkdir -p "$out/sbom"

yaml() { python3 - "$1" <<'PY'
import sys
want = sys.argv[1].split(".")
path = []
for raw in open("build/versions.yml"):
    line = raw.split("#", 1)[0].rstrip()
    if not line.strip() or line.strip() == "---":
        continue
    indent = (len(line) - len(line.lstrip())) // 2
    key, _, value = line.strip().partition(":")
    path = path[:indent] + [key]
    if path == want:
        print(value.strip())
        break
PY
}

target=$(yaml target)
hickory_version=$(yaml hickory.version)
edns_version=$(yaml encrypted_dns.version)
edns_sha=$(yaml encrypted_dns.crate_sha256)

echo "== hickory-dns ${hickory_version}"
cd /src/build/hickory-dns
grep -q "^hickory-dns = { version = \"=${hickory_version}\"" Cargo.toml \
  || { echo "Cargo.toml does not pin hickory-dns =${hickory_version}" >&2; exit 1; }
cargo deny --locked check advisories bans licenses  # reads deny.toml, a link to ../deny.toml
cargo audit --deny warnings --file Cargo.lock
# cargo tree prints nothing (and still exits 0) when a crate is absent.
if [ -n "$(cargo tree -q --locked --target "$target" -e normal,build -i ring 2>/dev/null)" ]; then
  echo "ring is in the hickory-dns build graph; aws-lc-rs must be the only TLS crypto provider" >&2
  exit 1
fi
if [ -z "$(cargo tree -q --locked --target "$target" -e normal,build -i aws-lc-rs 2>/dev/null)" ]; then
  echo "aws-lc-rs is missing from the hickory-dns build graph" >&2
  exit 1
fi
cargo auditable build --locked --release --target "$target"
install -m 0755 "target/$target/release/hickory-dns" "$out/hickory-dns"
cargo cyclonedx --format json --target "$target" --override-filename hickory-dns.cdx
mv hickory-dns.cdx.json "$out/sbom/"

echo "== encrypted-dns ${edns_version}"
work=$(mktemp -d)
curl -fsSL --retry 5 -o "$work/edns.crate" \
  "https://static.crates.io/crates/encrypted-dns/encrypted-dns-${edns_version}.crate"
echo "${edns_sha}  $work/edns.crate" | sha256sum -c -
tar -xzf "$work/edns.crate" -C "$work"
cd "$work/encrypted-dns-${edns_version}"
test -f Cargo.lock || { echo "the crate has no Cargo.lock" >&2; exit 1; }
cp /src/build/deny.toml deny.toml
cargo deny --locked check advisories
cargo audit --deny warnings --file Cargo.lock
cargo auditable build --locked --release --target "$target"
install -m 0755 "target/$target/release/encrypted-dns" "$out/encrypted-dns"
cargo cyclonedx --format json --target "$target" --override-filename encrypted-dns.cdx
mv encrypted-dns.cdx.json "$out/sbom/"

cd "$out"
cargo audit bin hickory-dns encrypted-dns
cp /src/build/native-inventory.md "$out/"
{
  echo "hickory-dns ${hickory_version}"
  echo "encrypted-dns ${edns_version}"
  echo "target ${target}"
  rustc --version
  cargo --version
  echo "source ${SOURCE_COMMIT:-unknown}"
} > BUILDINFO
sha256sum hickory-dns encrypted-dns > SHA256SUMS
cat SHA256SUMS
