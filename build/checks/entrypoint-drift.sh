#!/usr/bin/env bash
# Check that build/hickory-dns/src/main.rs is an unmodified copy of upstream's
# bin/src/hickory-dns.rs at the commit in build/versions.yml, and that
# Cargo.toml pins the same version.
#
# The commit is either a release tag (upstream_tag), which must still point at
# it, or a commit on an upstream branch (upstream_ref), which must be on that
# branch and match the git rev in Cargo.toml.
set -euo pipefail
cd "$(dirname "$0")/../.."

repo=https://github.com/hickory-dns/hickory-dns
get() { awk -v k="$1:" '$1 == k { print $2; exit }' build/versions.yml; }
version=$(awk '/^hickory:/{f=1;next} f && $1=="version:"{print $2; exit}' build/versions.yml)
tag=$(get upstream_tag)
ref=$(get upstream_ref)
commit=$(get upstream_commit)

grep -q "^hickory-dns = { version = \"=${version}\"" build/hickory-dns/Cargo.toml \
  || { echo "build/hickory-dns/Cargo.toml does not pin hickory-dns =${version}" >&2; exit 1; }
grep -q "^version = \"${version}\"" build/hickory-dns/Cargo.toml \
  || { echo "build/hickory-dns/Cargo.toml package version is not ${version}" >&2; exit 1; }

if [ -n "$tag" ]; then
  if grep -q '^hickory-dns = {.* git = ' build/hickory-dns/Cargo.toml; then
    echo "build/hickory-dns/Cargo.toml uses a git source, but build/versions.yml names a release tag" >&2
    exit 1
  fi
  resolved=$(git ls-remote "${repo}.git" "refs/tags/${tag}^{}" "refs/tags/${tag}" \
    | awk 'NR==1 || /\^\{\}$/ { sha=$1 } END { print sha }')
  [ "$resolved" = "$commit" ] \
    || { echo "tag ${tag} points at ${resolved}, expected ${commit}" >&2; exit 1; }
  source="${tag}"
elif [ -n "$ref" ]; then
  grep -q "^hickory-dns = {.* git = \"${repo}\", rev = \"${commit}\"" build/hickory-dns/Cargo.toml \
    || { echo "build/hickory-dns/Cargo.toml does not pin ${repo} at rev ${commit}" >&2; exit 1; }
  # "behind" or "identical" means the commit is on the branch.
  status=$(curl -fsSL --retry 5 -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/hickory-dns/hickory-dns/compare/${ref}...${commit}" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["status"])')
  case "$status" in
    behind|identical) ;;
    *) echo "commit ${commit} is not on upstream ${ref} (compare status: ${status})" >&2; exit 1 ;;
  esac
  source="${ref} at ${commit}"
else
  echo "build/versions.yml needs hickory.upstream_tag or hickory.upstream_ref" >&2
  exit 1
fi

upstream=$(mktemp)
curl -fsSL --retry 5 -o "$upstream" \
  "https://raw.githubusercontent.com/hickory-dns/hickory-dns/${commit}/bin/src/hickory-dns.rs"
if ! diff -u "$upstream" build/hickory-dns/src/main.rs; then
  echo "build/hickory-dns/src/main.rs differs from upstream ${source}. Copy the upstream file again." >&2
  exit 1
fi
echo "entrypoint matches upstream ${source} (${commit})"
