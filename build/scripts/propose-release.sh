#!/usr/bin/env bash
# Open one pull request that points defaults/main.yml at a new binary release:
# the release tag, both download URLs and both SHA-256 sums change together.
#
# Usage: propose-release.sh <tag> <SHA256SUMS file>
set -euo pipefail

tag=$1
sums=$2
defaults=defaults/main.yml

if ! grep -q '^dns_resolver_binary_release:' "$defaults"; then
  echo "defaults/main.yml has no binary variables yet; nothing to propose."
  exit 0
fi

repo=${GITHUB_REPOSITORY:?}
base="https://github.com/${repo}/releases/download/${tag}"
hickory_sha=$(awk '$2 == "hickory-dns" { print $1 }' "$sums")
edns_sha=$(awk '$2 == "encrypted-dns" { print $1 }' "$sums")

set_var() {
  sed -i -E "s|^($1:).*|\\1 \"$2\"|" "$defaults"
}
set_var dns_resolver_binary_release "$tag"
set_var dns_resolver_hickory_url "${base}/hickory-dns"
set_var dns_resolver_hickory_sha256 "$hickory_sha"
set_var dns_resolver_encrypted_dns_url "${base}/encrypted-dns"
set_var dns_resolver_encrypted_dns_sha256 "$edns_sha"

branch="release/${tag}"
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git switch -c "$branch"
git commit -am "Use binary release ${tag}"
git push "https://x-access-token:${GH_TOKEN}@github.com/${repo}.git" "$branch"
gh pr create --base main --head "$branch" \
  --title "Use binary release ${tag}" \
  --body "Points the role at release ${tag}. The URLs and SHA-256 sums change together. Molecule runs against these binaries in this PR."
