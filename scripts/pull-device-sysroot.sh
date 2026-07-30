#!/usr/bin/env bash
# Build an aarch64 sysroot by copying libraries and headers from a running
# target over SSH. Use this when you want the sysroot to match a specific
# device's ABI exactly (its glibc, libtss2, and libcrypto versions), so the
# cross-built binary is guaranteed to run there.
#
# The target must have libtss2 installed (its dev symlinks and pkg-config .pc
# files) and be reachable over key-based SSH. The resulting sysroot is consumed
# by scripts/cross-build-aarch64.sh via SYSROOT=<dir>.
#
# Usage:
#   ./scripts/pull-device-sysroot.sh user@host [sysroot-dir]
set -euo pipefail

TARGET_SSH="${1:-}"
SYSROOT="${2:-$(cd "$(dirname "$0")/.." && pwd)/.build/aarch64-sysroot}"

if [[ -z "$TARGET_SSH" ]]; then
  echo "Usage: $0 user@host [sysroot-dir]" >&2
  exit 1
fi

mkdir -p "$SYSROOT/usr"
echo "Copying /usr/lib and /usr/include from $TARGET_SSH into $SYSROOT ..."
rsync -a --info=stats1 -e "ssh -o BatchMode=yes" \
  "$TARGET_SSH:/usr/lib" "$TARGET_SSH:/usr/include" \
  "$SYSROOT/usr/"

# Recreate a usrmerge layout so /lib and /lib64 resolve during linking.
ln -sfn usr/lib "$SYSROOT/lib"
ln -sfn usr/lib "$SYSROOT/lib64"

echo "Sysroot ready at: $SYSROOT"
if [[ -e "$SYSROOT/usr/lib/libtss2-esys.so" || -e "$SYSROOT/usr/lib/aarch64-linux-gnu/libtss2-esys.so" ]]; then
  echo "libtss2-esys found — ready for: SYSROOT=$SYSROOT ./scripts/cross-build-aarch64.sh"
else
  echo "WARNING: libtss2-esys.so not found in sysroot — is libtss2 installed on the target?" >&2
fi
