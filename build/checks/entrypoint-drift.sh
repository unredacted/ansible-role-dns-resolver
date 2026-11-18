#!/usr/bin/env bash
# Check that build/hickory-dns/src/main.rs is an unmodified copy of upstream's
# bin/src/hickory-dns.rs at the tag in build/versions.yml, that the tag still
# points at the recorded commit, and that Cargo.toml pins the same version.
set -euo pipefail
cd "$(dirname "$0")/../.."

get() { awk -v k="$1:" '$1 == k { print $2; exit }' build/versions.yml; }
version=$(awk '/^hickory:/{f=1;next} f && $1=="version:"{print $2; exit}' build/versions.yml)
tag=$(get upstream_tag)
commit=$(get upstream_commit)

grep -q "^hickory-dns = { version = \"=${version}\"" build/hickory-dns/Cargo.toml \
  || { echo "build/hickory-dns/Cargo.toml does not pin hickory-dns =${version}" >&2; exit 1; }
grep -q "^version = \"${version}\"" build/hickory-dns/Cargo.toml \
  || { echo "build/hickory-dns/Cargo.toml package version is not ${version}" >&2; exit 1; }

resolved=$(git ls-remote https://github.com/hickory-dns/hickory-dns.git "refs/tags/${tag}^{}" "refs/tags/${tag}" \
  | awk 'NR==1 || /\^\{\}$/ { sha=$1 } END { print sha }')
[ "$resolved" = "$commit" ] \
  || { echo "tag ${tag} points at ${resolved}, expected ${commit}" >&2; exit 1; }

upstream=$(mktemp)
curl -fsSL --retry 5 -o "$upstream" \
  "https://raw.githubusercontent.com/hickory-dns/hickory-dns/${commit}/bin/src/hickory-dns.rs"
if ! diff -u "$upstream" build/hickory-dns/src/main.rs; then
  echo "build/hickory-dns/src/main.rs differs from upstream ${tag}. Copy the upstream file again." >&2
  exit 1
fi
echo "entrypoint matches upstream ${tag} (${commit})"
