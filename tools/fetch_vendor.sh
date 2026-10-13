#!/usr/bin/env bash
# Fetch and unpack Redragon's Windows control panel for the M910-KS.
#
# This is the provenance script for docs/GUI-ANALYSIS.md. Everything the
# protocol analysis rests on is reproducible from here: the download is
# checksum-verified, the extraction is pinned, and the vendor binaries land
# in vendor/ (gitignored -- they are Redragon's IP, never committed).
#
# UNPRIVILEGED BY DESIGN. Nothing is installed and sudo is never invoked.
# innoextract is unpacked from an Arch package file into vendor/tools/ and
# run from there. The RAR itself is handled by bsdtar, which is already
# installed.
#
#   ./tools/fetch_vendor.sh          # fetch + unpack
#   ./tools/fetch_vendor.sh --clean  # remove vendor/ and start over
#
# Requires: bash, curl, bsdtar (libarchive), tar, sha256sum, python3.
# Test artifacts land in vendor/, which .gitignore already excludes.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$REPO/vendor"

RAR_NAME="Redragon_M910KS_Setup_v1.0_2876_BY1064_P3104.rar"
RAR_URL="https://cdn.shopify.com/s/files/1/0655/1289/8735/files/Redragon_M910KS_Setup_v1.0_2876_BY1064_P3104.rar?v=1720771133"
RAR_SHA256="28d4e9e3528ab0ae073d6af03503805c693c6f1a35c9c319c08009e77e5ebf78"

# archive.archlinux.org is immutable, so the pinned version stays fetchable
# long after it leaves the rolling mirror.
INNO_PKG="innoextract-1.9-17-x86_64"
INNO_URL="https://archive.archlinux.org/packages/i/innoextract/${INNO_PKG}.pkg.tar.zst"

die() { echo "error: $*" >&2; exit 1; }
say() { echo "==> $*"; }

if [[ "${1:-}" == "--clean" ]]; then
    rm -rf "$VENDOR"
    echo "removed $VENDOR"
    exit 0
fi

command -v curl      >/dev/null || die "curl not found"
command -v bsdtar    >/dev/null || die "bsdtar not found (install libarchive)"
command -v sha256sum >/dev/null || die "sha256sum not found"

mkdir -p "$VENDOR/dl" "$VENDOR/tools" "$VENDOR/out"

# --- 1. the RAR -------------------------------------------------------------
RAR_PATH="$VENDOR/dl/$RAR_NAME"
if [[ -f "$RAR_PATH" ]] && \
   echo "$RAR_SHA256  $RAR_PATH" | sha256sum -c --status; then
    say "RAR already present and verified"
else
    say "downloading $RAR_NAME"
    curl -fsSL --retry 3 -o "$RAR_PATH" "$RAR_URL" \
        || die "download failed: $RAR_URL"
    echo "$RAR_SHA256  $RAR_PATH" | sha256sum -c --status \
        || die "sha256 mismatch -- refusing to continue"
    say "sha256 verified"
fi

# --- 2. the Inno Setup loader ----------------------------------------------
SETUP="$VENDOR/out/$RAR_NAME.stage1/setup.exe"
if [[ ! -f "$SETUP" ]]; then
    say "extracting RAR (bsdtar)"
    STAGE="$VENDOR/out/${RAR_NAME}.stage1"
    mkdir -p "$STAGE"
    bsdtar -xf "$RAR_PATH" -C "$STAGE" || die "bsdtar could not read the RAR"
fi
[[ -f "$SETUP" ]] || die "setup.exe not found after extraction"
say "setup.exe: $(stat -c%s "$SETUP") bytes"

# --- 3. innoextract, unpacked locally --------------------------------------
if [[ ! -x "$VENDOR/tools/$INNO_PKG/usr/bin/innoextract" ]]; then
    command -v innoextract >/dev/null && INNO="$VENDOR/tools/innoextract-system"
    if [[ -z "${INNO:-}" ]]; then
        say "fetching $INNO_PKG (unprivileged)"
        curl -fsSL --retry 3 -o "$VENDOR/dl/${INNO_PKG}.pkg.tar.zst" "$INNO_URL" \
            || die "could not fetch innoextract: $INNO_URL"
        mkdir -p "$VENDOR/tools/$INNO_PKG"
        bsdtar -xf "$VENDOR/dl/${INNO_PKG}.pkg.tar.zst" -C "$VENDOR/tools/$INNO_PKG"
    fi
    INNO="$VENDOR/tools/$INNO_PKG/usr/bin/innoextract"
fi
[[ -x "$INNO" ]] || die "innoextract unavailable"
say "innoextract: $("$INNO" --version | head -1)"

# --- 4. the payload ---------------------------------------------------------
if [[ ! -d "$VENDOR/gui/app" ]]; then
    say "extracting Inno Setup payload"
    "$INNO" -e --collisions rename-all -d "$VENDOR/gui" "$SETUP" \
        || die "innoextract failed"
fi

# --- 5. manifest ------------------------------------------------------------
MANIFEST="$VENDOR/MANIFEST.txt"
{
    echo "Vendor artifacts for docs/GUI-ANALYSIS.md"
    echo "Fetched by tools/fetch_vendor.sh -- do not commit (see .gitignore)"
    echo
    echo "source: $RAR_URL"
    echo "sha256: $RAR_SHA256  $RAR_NAME"
    echo
    echo "payload:"
    find "$VENDOR/gui" -type f ! -path '*/skins/*' -printf '%10s  %P\n' \
        | sort -k2
    echo
    echo "skins: $(find "$VENDOR/gui" -path '*/skins/*' -type f | wc -l) files (omitted)"
    echo
    echo "binary hashes:"
    find "$VENDOR/gui/app" -maxdepth 1 -type f \
        \( -name '*.exe' -o -name '*.dll' \) -exec sha256sum {} +
} > "$MANIFEST"

say "done -> $VENDOR"
echo
echo "Key files:"
echo "  $VENDOR/gui/app/OemDrv.exe     GUI + all protocol logic"
echo "  $VENDOR/gui/app/Lowerdev.dll    HID transport shim"
echo "  $VENDOR/gui/app/Cfg.ini         device database / feature vocabulary"
echo "  $VENDOR/gui/app/Text/en/text.xml UI strings"
echo "  $MANIFEST"