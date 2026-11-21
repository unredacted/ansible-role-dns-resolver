#!/usr/bin/env bash
# Open one pull request that points defaults/main.yml at a new binary release:
# the release tag, both download URLs, both SHA-256 sums and what the build
# supports (dns_resolver_doh_get_supported) change together.
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
branch="release/${tag}"
remote="https://x-access-token:${GH_TOKEN}@github.com/${repo}.git"

open_pr() {
  gh pr create --base main --head "$branch" \
    --title "Use binary release ${tag}" \
    --body "Points the role at release ${tag}. The URLs, the SHA-256 sums and dns_resolver_doh_get_supported change together. Molecule runs against these binaries in this PR."
}

# Safe to rerun: skip the parts that already happened.
if [ -n "$(gh pr list --head "$branch" --state open --json number --jq '.[0].number // empty')" ]; then
  echo "A pull request for ${branch} is already open."
  exit 0
fi
if git ls-remote --exit-code --heads "$remote" "$branch" >/dev/null; then
  echo "Branch ${branch} exists; opening the pull request for it."
  open_pr
  exit 0
fi

# What the released build supports, from the inputs it was built from.
doh_get=$(awk '/^hickory:/ { f = 1; next } /^[^ #]/ { f = 0 } f && $1 == "doh_get:" { print $2; exit }' build/versions.yml)
case "${doh_get:-false}" in
  true|false) ;;
  *) echo "hickory.doh_get in build/versions.yml must be true or false, not ${doh_get}" >&2; exit 1 ;;
esac

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
sed -i -E "s|^(dns_resolver_doh_get_supported:).*|\\1 ${doh_get:-false}|" "$defaults"

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git switch -c "$branch"
git commit -am "Use binary release ${tag}"
git push "$remote" "$branch"
open_pr
