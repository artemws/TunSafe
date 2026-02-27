#!/usr/bin/env bash
# Inject .so files into an existing APK and re-sign it.
# Usage:
#   inject_so.sh --apk BASE.apk --out OUT.apk --libs LIBS_DIR \
#                --keystore KS --key-alias ALIAS \
#                --storepass PASS --keypass PASS
set -euo pipefail

APK="" OUT="" LIBS="" KS="" ALIAS="" STOREPASS="" KEYPASS=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --apk)       APK="$2";       shift 2 ;;
    --out)       OUT="$2";       shift 2 ;;
    --libs)      LIBS="$2";      shift 2 ;;
    --keystore)  KS="$2";        shift 2 ;;
    --key-alias) ALIAS="$2";     shift 2 ;;
    --storepass) STOREPASS="$2"; shift 2 ;;
    --keypass)   KEYPASS="$2";   shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

[[ -f "$APK" ]] || { echo "ERROR: APK not found: $APK"; exit 1; }
[[ -d "$LIBS" ]] || { echo "ERROR: libs dir not found: $LIBS"; exit 1; }

WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT

# Unzip base APK
cp "$APK" "$WORKDIR/base.apk"
cd "$WORKDIR"
unzip -q base.apk -d apk_contents

# Inject .so files for each ABI
# The .so built by CMake is libnative-lib.so but the app loads libtunsafe.so
for ABI_DIR in "$LIBS"/*/; do
  ABI=$(basename "$ABI_DIR")
  mkdir -p "apk_contents/lib/$ABI"
  for SO in "$ABI_DIR"*.so; do
    [[ -f "$SO" ]] || continue
    SONAME=$(basename "$SO")
    # .so is already named libtunsafe.so (built with add_library(tunsafe ...))
    cp "$SO" "apk_contents/lib/$ABI/$SONAME"
    echo "Injected: lib/$ABI/$SONAME"
  done
done

# Repackage
cd apk_contents
zip -qr "$WORKDIR/unsigned.apk" .
cd "$WORKDIR"

# Align
zipalign -f 4 unsigned.apk aligned.apk

# Sign
apksigner sign \
  --ks "$KS" \
  --ks-key-alias "$ALIAS" \
  --ks-pass "pass:$STOREPASS" \
  --key-pass "pass:$KEYPASS" \
  --out "$OLDPWD/$OUT" \
  aligned.apk

echo "APK ready: $OUT"
