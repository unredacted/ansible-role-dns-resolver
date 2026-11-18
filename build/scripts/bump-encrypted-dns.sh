#!/usr/bin/env bash
# Dependabot cannot follow encrypted-dns, because it is a binary-only crate.
# This script checks crates.io for a newer release and, if there is one, opens
# a pull request that updates the version and the .crate checksum in
# build/versions.yml.
set -euo pipefail

file=build/versions.yml
current=$(awk '/^encrypted_dns:/{f=1;next} f && $1=="version:"{print $2; exit}' "$file")
latest=$(curl -fsSL -H 'User-Agent: ansible-role-dns-resolver (bump check)' \
  https://crates.io/api/v1/crates/encrypted-dns | python3 -c 'import json,sys; print(json.load(sys.stdin)["crate"]["max_stable_version"])')

if [ "$current" = "$latest" ]; then
  echo "encrypted-dns ${current} is current."
  exit 0
fi

branch="bump/encrypted-dns-${latest}"
if git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
  echo "A branch for ${latest} already exists."
  exit 0
fi

sha=$(curl -fsSL -H 'User-Agent: ansible-role-dns-resolver (bump check)' \
  https://index.crates.io/en/cr/encrypted-dns \
  | LATEST="$latest" python3 -c 'import json,os,sys
for line in sys.stdin:
    entry = json.loads(line)
    if entry["vers"] == os.environ["LATEST"]:
        print(entry["cksum"])')
[ -n "$sha" ] || { echo "no checksum for ${latest} in the index" >&2; exit 1; }

python3 - "$file" "$latest" "$sha" <<'PY'
import sys
path, version, sha = sys.argv[1:]
lines = open(path).read().splitlines(keepends=True)
section = None
for i, line in enumerate(lines):
    if line and not line.startswith(" ") and line.rstrip().endswith(":"):
        section = line.strip()[:-1]
    if section == "encrypted_dns":
        key = line.strip().split(":", 1)[0]
        if key == "version":
            lines[i] = f"  version: {version}\n"
        elif key == "crate_sha256":
            lines[i] = f"  crate_sha256: {sha}\n"
open(path, "w").write("".join(lines))
PY

repo=${GITHUB_REPOSITORY:?}
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git switch -c "$branch"
git commit -am "Bump encrypted-dns from ${current} to ${latest}"
git push "https://x-access-token:${GH_TOKEN}@github.com/${repo}.git" "$branch"
gh pr create --base main --head "$branch" \
  --title "Bump encrypted-dns from ${current} to ${latest}" \
  --body "New upstream release: https://github.com/DNSCrypt/encrypted-dns-server/releases. Check the changelog for config changes before merging."
