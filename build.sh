#!/usr/bin/env bash
# Build the multi-platform release into dist/ (+ SHA256SUMS).
# Usage:  ./build.sh [version]      e.g.  ./build.sh v1.0.0
set -euo pipefail
cd "$(dirname "$0")"

version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

rm -rf dist && mkdir -p dist
for t in $targets; do
  os="${t%/*}"; arch="${t#*/}"
  out="dist/snmpapply-${os}-${arch}"
  [ "$os" = windows ] && out="${out}.exe"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags="-s -w -X main.version=${version}" -o "$out" ./cmd/snmpapply
  echo "  ✓ $out"
done

# Checksums of the binaries only (sha256sum on Linux, shasum on macOS).
( cd dist && { command -v sha256sum >/dev/null && sha256sum snmpapply-* || shasum -a 256 snmpapply-*; } > SHA256SUMS )
echo "Listo — versión ${version}, $(ls dist/snmpapply-* | wc -l) binarios + SHA256SUMS"
