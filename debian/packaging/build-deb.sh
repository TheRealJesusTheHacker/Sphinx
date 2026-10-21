#!/bin/sh
# Build the Sphinx Debian package (Phase 1) with dpkg-deb.
#
# Usage: sh debian/packaging/build-deb.sh [output-dir]
#
# The package is assembled from this repository checkout: the Python
# sources from debian/src, the systemd unit and maintainer scripts
# from debian/packaging, the docs from debian/README.md, and the
# bundled blocklist copied from the canonical asset the Android
# edition ships (app/src/main/assets/bundled-blocklist.txt) — copied
# at build time and byte-checked, never forked into this tree, so
# the editions cannot drift apart.
set -eu

HERE=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)
DEBIAN_DIR=$(dirname "$HERE")
REPO_ROOT=$(dirname "$DEBIAN_DIR")
SRC="$DEBIAN_DIR/src/sphinx_deb"
CANONICAL_LIST="$REPO_ROOT/app/src/main/assets/bundled-blocklist.txt"
OUT_DIR=${1:-"$DEBIAN_DIR/dist"}

VERSION=$(sed -n 's/^__version__ = "\([^"]*\)"$/\1/p' "$SRC/__init__.py")
if [ -z "$VERSION" ]; then
    echo "build-deb: could not read __version__ from $SRC/__init__.py" >&2
    exit 1
fi
if [ ! -f "$CANONICAL_LIST" ]; then
    echo "build-deb: the canonical bundled blocklist is missing: $CANONICAL_LIST" >&2
    exit 1
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT INT TERM
# dpkg-deb insists the control directory sit at 0755..0775; the
# staging dir's inherited permissions are not guaranteed to.
chmod 0755 "$STAGE"

mkdir -p \
    "$STAGE/usr/lib/sphinx" \
    "$STAGE/usr/bin" \
    "$STAGE/usr/share/sphinx" \
    "$STAGE/usr/share/doc/sphinx" \
    "$STAGE/etc/sphinx" \
    "$STAGE/lib/systemd/system" \
    "$STAGE/DEBIAN"

cp -r "$SRC" "$STAGE/usr/lib/sphinx/"
find "$STAGE/usr/lib/sphinx" -name __pycache__ -type d -prune -exec rm -rf {} +

# The bundled list: the canonical asset, copied and byte-checked.
cp "$CANONICAL_LIST" "$STAGE/usr/share/sphinx/bundled-blocklist.txt"
cmp "$CANONICAL_LIST" "$STAGE/usr/share/sphinx/bundled-blocklist.txt"

cp "$HERE/sphinx" "$STAGE/usr/bin/sphinx"
chmod 755 "$STAGE/usr/bin/sphinx"

cp "$HERE/sphinx.conf" "$STAGE/etc/sphinx/sphinx.conf"
cp "$HERE/sphinx.service" "$STAGE/lib/systemd/system/sphinx.service"
cp "$DEBIAN_DIR/README.md" "$STAGE/usr/share/doc/sphinx/README.md"

chmod 0755 "$STAGE/DEBIAN"
for f in control postinst prerm postrm conffiles; do
    sed "s/@VERSION@/$VERSION/g" "$HERE/$f" > "$STAGE/DEBIAN/$f"
done
chmod 755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"
chmod 644 "$STAGE/DEBIAN/control" "$STAGE/DEBIAN/conffiles"
chmod 644 \
    "$STAGE/etc/sphinx/sphinx.conf" \
    "$STAGE/lib/systemd/system/sphinx.service" \
    "$STAGE/usr/share/doc/sphinx/README.md" \
    "$STAGE/usr/share/sphinx/bundled-blocklist.txt"

# Normalize payload permissions (0644 files, 0755 directories and the
# one executable) regardless of the build host's umask, so the
# package is the same package everywhere.
find "$STAGE/usr" "$STAGE/etc" "$STAGE/lib" -type d -exec chmod 0755 {} +
find "$STAGE/usr" "$STAGE/etc" "$STAGE/lib" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/usr/bin/sphinx"

mkdir -p "$OUT_DIR"
PKG="$OUT_DIR/sphinx_${VERSION}_all.deb"
rm -f "$PKG"
dpkg-deb --build "$STAGE" "$PKG" >/dev/null
(
    cd "$OUT_DIR"
    sha256sum "sphinx_${VERSION}_all.deb" > SHA256SUMS.txt
)
echo "built: $PKG"
ls -l "$PKG"
