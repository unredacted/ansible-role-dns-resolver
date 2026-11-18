#!/usr/bin/env bash
# Build the builder image and run build/build.sh in it.
# Needs Docker (or Podman with DOCKER=podman).
set -euo pipefail

cd "$(dirname "$0")/.."
docker=${DOCKER:-docker}
# The release target is x86_64; force an amd64 builder so this also works on arm64 machines.
platform=${BUILD_PLATFORM:-linux/amd64}

tool() { python3 - "$1" <<'PY'
import sys
for raw in open("build/versions.yml"):
    line = raw.split("#", 1)[0].strip()
    if line.startswith(sys.argv[1] + ":"):
        print(line.split(":", 1)[1].strip())
PY
}

"$docker" build --platform "$platform" \
  --build-arg "CARGO_AUDITABLE_VERSION=$(tool cargo_auditable)" \
  --build-arg "CARGO_DENY_VERSION=$(tool cargo_deny)" \
  --build-arg "CARGO_AUDIT_VERSION=$(tool cargo_audit)" \
  --build-arg "CARGO_CYCLONEDX_VERSION=$(tool cargo_cyclonedx)" \
  -t dns-resolver-builder -f build/Dockerfile build

# Run as the calling user so artifacts/ and target/ stay owned by them.
# Cargo's own home in the image belongs to root, so use a scratch one.
user_args=(--user "$(id -u):$(id -g)" -e HOME=/tmp -e CARGO_HOME=/tmp/cargo-home)
case "$docker" in
  *podman*) user_args+=(--userns=keep-id) ;;
esac

"$docker" run --rm --platform "$platform" "${user_args[@]}" \
  -e "SOURCE_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
  -v "$PWD:/src" \
  dns-resolver-builder bash build/build.sh
