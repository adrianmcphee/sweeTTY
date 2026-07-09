#!/usr/bin/env bash
# Build cross-platform release archives for sweetty, with checksums. Run by the
# release workflow on a tag, and usable locally for a dry run (make release-local).
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --exact-match 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || echo dev)}"
GIT_COMMIT="${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
OUT="${OUT:-dist}"
VER_NOV="${VERSION#v}"

if [[ ! "$VERSION" =~ ^v[0-9A-Za-z][0-9A-Za-z._-]*$ ]]; then
  echo "invalid VERSION: must be a safe v-prefixed release token" >&2
  exit 2
fi
if [[ "$OUT" != "dist" ]]; then
  echo "OUT must be the repository dist directory" >&2
  exit 2
fi

LDFLAGS="-s -w -X main.version=${VERSION} -X main.gitCommit=${GIT_COMMIT} -X main.buildDate=${BUILD_DATE}"

targets=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
)

rm -rf -- "$OUT"
mkdir -p "$OUT"

for t in "${targets[@]}"; do
  goos="${t%/*}"
  goarch="${t#*/}"
  stage="$(mktemp -d)"
  echo "building ${goos}/${goarch}"
  # Build a fully static binary (CGO disabled, no -buildmode=pie). The deployment
  # runs the honeypot under a systemd unit with NoExecPaths=/ scoped to the single
  # slot binary, as the strongest layer of post-RCE containment. A Go PIE keeps a
  # PT_INTERP (the dynamic loader), which that unit cannot exec, so a PIE binary
  # dies at startup with 203/EXEC. A static ET_EXEC has no interpreter, satisfies
  # NoExecPaths, and matches the "statically linked, self-contained" promise in the
  # README and VISION. Image-base ASLR is traded for that self-containment; the
  # kernel still randomizes stack/heap/mmap, and the unit adds W^X and a
  # seccomp execve-deny on top.
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$stage/sweetty" ./cmd/sweetty
  for f in README.md VISION.md LICENSE; do
    if [ -L "$f" ]; then
      echo "refusing symlink documentation file: $f" >&2
      exit 2
    fi
    [ -f "$f" ] && cp -- "$f" "$stage/"
  done
  tar -C "$stage" -czf "$OUT/sweetty_${VER_NOV}_${goos}_${goarch}.tar.gz" .
  rm -rf "$stage"
done

# Bare filenames (no ./ prefix), so a consumer can `grep "  <asset>$"` and
# `sha256sum -c` the entry directly. A ./ prefix breaks that exact-suffix match.
( cd "$OUT" && files=(); for f in ./*.tar.gz; do files+=("${f#./}"); done; { sha256sum -- "${files[@]}" 2>/dev/null || shasum -a 256 "${files[@]}"; } > checksums.txt )

echo "artifacts in ${OUT}:"
ls -1 "$OUT"
