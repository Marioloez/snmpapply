#!/usr/bin/env sh
# Installer for snmpapply: detects your OS/arch, downloads the matching binary
# from GitHub Releases, verifies its checksum and drops it in the current
# folder. Then create inventory.json + .env next to it and run ./snmpapply.
#
#   curl -fsSL https://raw.githubusercontent.com/Marioloez/snmpapply/main/install.sh | sh
#
# Override the version with:  VERSION=v1.0.0 sh install.sh
set -eu

REPO="Marioloez/snmpapply"   # GitHub "owner/repo"
VERSION="${VERSION:-latest}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) echo "arquitectura no soportada: $arch" >&2; exit 1 ;;
esac
case "$os" in
  linux | darwin) ;;
  *) echo "SO no soportado: $os (¿Windows? descarga el .exe desde la página de Releases)" >&2; exit 1 ;;
esac

asset="snmpapply-${os}-${arch}"
if [ "$VERSION" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  base="https://github.com/${REPO}/releases/download/${VERSION}"
fi

echo "Descargando ${asset} (${VERSION})…"
curl -fsSL "${base}/${asset}" -o "${asset}"

# Verify checksum if SHA256SUMS is published alongside the binaries.
if curl -fsSL "${base}/SHA256SUMS" -o SHA256SUMS 2>/dev/null; then
  if command -v sha256sum >/dev/null 2>&1; then
    grep " \./${asset}\$\| ${asset}\$" SHA256SUMS | sed "s#\./##" | sha256sum -c - \
      || { echo "checksum FALLÓ" >&2; rm -f "${asset}" SHA256SUMS; exit 1; }
  elif command -v shasum >/dev/null 2>&1; then
    grep " \./${asset}\$\| ${asset}\$" SHA256SUMS | sed "s#\./##" | shasum -a 256 -c - \
      || { echo "checksum FALLÓ" >&2; rm -f "${asset}" SHA256SUMS; exit 1; }
  fi
  rm -f SHA256SUMS
  echo "checksum OK"
fi

mv "${asset}" snmpapply
chmod +x snmpapply

# Drop the example templates too, so the shape of inventory.json and .env is
# obvious without leaving this folder. Fetched from the repo (raw) so the real
# filenames are preserved — GitHub release assets can't start with a dot.
# Best-effort: never fails the install, and an existing file is left untouched.
raw="https://raw.githubusercontent.com/${REPO}/main"
for tpl in .env.example inventory.example.json; do
  [ -e "${tpl}" ] && continue
  curl -fsSL "${raw}/${tpl}" -o "${tpl}" 2>/dev/null && echo "plantilla ${tpl} ✓" || true
done

echo "✅ Listo. Copia .env.example a .env e inventory.example.json a inventory.json,"
echo "   complétalos y ejecuta: ./snmpapply"
