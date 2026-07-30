#!/usr/bin/env bash
# Cross-compile tpm-ops for an aarch64 Linux target.
#
# tpm-ops links tss-esapi, which pulls in the C library libtss2, so a cross
# build needs an aarch64 *sysroot* that provides libtss2 (plus glibc, the crt
# startup objects, and libcrypto). Point $SYSROOT at one — see the
# "Cross-compiling for aarch64" section of the README for ways to obtain a
# sysroot (arm64 multiarch packages, a copy from your target device, or a
# Yocto/vendor SDK).
#
# Prereqs:
#   - aarch64-linux-gnu-gcc         (Debian/Ubuntu: apt install gcc-aarch64-linux-gnu)
#   - rustup target add aarch64-unknown-linux-gnu
#   - an aarch64 sysroot providing libtss2, at $SYSROOT
#
# Usage:
#   SYSROOT=/path/to/aarch64-sysroot ./scripts/cross-build-aarch64.sh [extra cargo args]
set -euo pipefail

SYSROOT="${SYSROOT:-$(cd "$(dirname "$0")/.." && pwd)/.build/aarch64-sysroot}"
TARGET="${TARGET:-aarch64-unknown-linux-gnu}"
CROSS_GCC="${CROSS_GCC:-aarch64-linux-gnu-gcc}"

if [[ ! -e "$SYSROOT/usr/lib/libtss2-esys.so" \
   && ! -e "$SYSROOT/usr/lib/aarch64-linux-gnu/libtss2-esys.so" ]]; then
  echo "No aarch64 libtss2 found under SYSROOT=$SYSROOT" >&2
  echo "Set SYSROOT to an aarch64 sysroot that provides libtss2 (see README)." >&2
  exit 1
fi

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$CROSS_GCC"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=--sysroot=$SYSROOT"
export CC_aarch64_unknown_linux_gnu="$CROSS_GCC"

# pkg-config must resolve tss2-* from the sysroot, not the host. Cover both the
# usrmerge (/usr/lib/pkgconfig) and Debian multiarch layouts.
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_SYSROOT_DIR="$SYSROOT"
export PKG_CONFIG_LIBDIR="$SYSROOT/usr/lib/pkgconfig:$SYSROOT/usr/lib/aarch64-linux-gnu/pkgconfig:$SYSROOT/usr/share/pkgconfig"

echo "Sysroot: $SYSROOT"
echo "Building tpm-ops for $TARGET ..."
cargo build --target "$TARGET" --release --locked "$@"

BIN="target/$TARGET/release/tpm-ops"
echo
echo "=== built: $BIN ==="
file "$BIN"
if command -v aarch64-linux-gnu-readelf >/dev/null 2>&1; then
  echo "--- NEEDED libraries ---"
  aarch64-linux-gnu-readelf -d "$BIN" | grep NEEDED || true
  echo "--- max GLIBC symbol version required (must be <= your target's glibc) ---"
  aarch64-linux-gnu-readelf -V "$BIN" 2>/dev/null \
    | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -uV | tail -3 || true
fi
