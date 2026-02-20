#!/usr/bin/env bash
# inject_so.sh
# ─────────────────────────────────────────────────────────────────────────────
# Replaces libnative-lib.so in a TunSafe APK with freshly built versions,
# re-aligns the APK (zipalign) and signs it (apksigner).
#
# Usage:
#   ./inject_so.sh [OPTIONS]
#
# Options:
#   --apk        PATH   Input APK  (default: TunSafe-Android.apk)
#   --out        PATH   Output APK (default: TunSafe-Android-new.apk)
#   --libs       DIR    Directory containing ABI sub-dirs with .so files
#                       (default: ./build/android/libs)
#   --keystore   PATH   Keystore file for signing
#   --key-alias  ALIAS  Key alias   (default: tunsafe)
#   --storepass  PASS   Keystore password (or use env KEYSTORE_PASS)
#   --keypass    PASS   Key password      (or use env KEY_PASS)
#   --create-ks         Generate a debug keystore if none exists
#
# Expected --libs directory layout:
#   libs/
#     arm64-v8a/libnative-lib.so
#     armeabi-v7a/libnative-lib.so
#     x86_64/libnative-lib.so      (optional)
#     x86/libnative-lib.so         (optional)
#
# Requirements: unzip, zip, zipalign, apksigner (Android build-tools)
# All tools are available in the Android SDK or via apt/brew.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
INPUT_APK="TunSafe-Android.apk"
OUTPUT_APK="TunSafe-Android-new.apk"
LIBS_DIR="./build/android/libs"
KEYSTORE=""
KEY_ALIAS="tunsafe"
STOREPASS="${KEYSTORE_PASS:-}"
KEYPASS="${KEY_PASS:-}"
CREATE_KS=0

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --apk)       INPUT_APK="$2";  shift 2 ;;
        --out)       OUTPUT_APK="$2"; shift 2 ;;
        --libs)      LIBS_DIR="$2";   shift 2 ;;
        --keystore)  KEYSTORE="$2";   shift 2 ;;
        --key-alias) KEY_ALIAS="$2";  shift 2 ;;
        --storepass) STOREPASS="$2";  shift 2 ;;
        --keypass)   KEYPASS="$2";    shift 2 ;;
        --create-ks) CREATE_KS=1;     shift   ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[inject_so]${NC} $*"; }
warn()    { echo -e "${YELLOW}[inject_so] WARN:${NC} $*"; }
die()     { echo -e "${RED}[inject_so] ERROR:${NC} $*" >&2; exit 1; }

# ── Tool checks ───────────────────────────────────────────────────────────────
need() { command -v "$1" &>/dev/null || die "'$1' not found. Install Android SDK build-tools or apt install $2."; }
need unzip     unzip
need zip       zip
need zipalign  "android-sdk (zipalign)"
need apksigner "android-sdk (apksigner)"

# ── Keystore setup ────────────────────────────────────────────────────────────
if [[ -z "$KEYSTORE" ]]; then
    KEYSTORE="$(dirname "$OUTPUT_APK")/debug.keystore"
    CREATE_KS=1
fi

if [[ $CREATE_KS -eq 1 && ! -f "$KEYSTORE" ]]; then
    warn "No keystore found — generating debug keystore at $KEYSTORE"
    STOREPASS="${STOREPASS:-debugpass}"
    KEYPASS="${KEYPASS:-debugpass}"
    keytool -genkeypair \
        -keystore "$KEYSTORE" \
        -alias "$KEY_ALIAS" \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -storepass "$STOREPASS" -keypass "$KEYPASS" \
        -dname "CN=TunSafe Debug,O=Debug,C=US" \
        -noprompt
    info "Debug keystore created: $KEYSTORE"
fi

[[ -f "$KEYSTORE" ]] || die "Keystore not found: $KEYSTORE"
[[ -f "$INPUT_APK" ]] || die "Input APK not found: $INPUT_APK"
[[ -d "$LIBS_DIR" ]]  || die "Libs directory not found: $LIBS_DIR"

if [[ -z "$STOREPASS" ]]; then
    read -rsp "Keystore password: " STOREPASS; echo
fi
if [[ -z "$KEYPASS" ]]; then
    read -rsp "Key password: " KEYPASS; echo
fi

# ── Work directory ────────────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

info "Working directory: $WORK_DIR"
info "Input APK:         $INPUT_APK"
info "Libs directory:    $LIBS_DIR"

# ── Extract APK ───────────────────────────────────────────────────────────────
info "Extracting APK..."
cp "$INPUT_APK" "$WORK_DIR/original.apk"
cd "$WORK_DIR"
unzip -q original.apk -d apk_tree

# ── Verify lib structure in APK ───────────────────────────────────────────────
info "Checking existing .so files in APK..."
find apk_tree/lib -name "*.so" | sort | while read -r f; do
    info "  Found: ${f#apk_tree/}"
done

# ── Replace .so files ─────────────────────────────────────────────────────────
REPLACED=0
for ABI in arm64-v8a armeabi-v7a x86_64 x86; do
    SRC="$LIBS_DIR/$ABI/libnative-lib.so"
    DST="apk_tree/lib/$ABI/libnative-lib.so"
    if [[ -f "$SRC" && -d "apk_tree/lib/$ABI" ]]; then
        cp "$SRC" "$DST"
        info "  Replaced lib/$ABI/libnative-lib.so ($(du -sh "$SRC" | cut -f1))"
        REPLACED=$((REPLACED + 1))
    elif [[ -f "$SRC" && ! -d "apk_tree/lib/$ABI" ]]; then
        warn "  $ABI not in original APK, skipping"
    elif [[ ! -f "$SRC" ]]; then
        warn "  No built .so for $ABI at $SRC — keeping original"
    fi
done

[[ $REPLACED -gt 0 ]] || die "No .so files were replaced. Check --libs path."
info "Replaced $REPLACED .so file(s)."

# ── Remove original signature (META-INF) ─────────────────────────────────────
info "Removing original signature..."
rm -rf apk_tree/META-INF

# ── Repack APK (unsigned, unaligned) ─────────────────────────────────────────
info "Repacking APK..."
cd apk_tree
# Use 'zip -0' for uncompressed entries (resources.arsc, .so, .png)
# and default compression for everything else.
# The correct approach: store uncompressed what Android requires uncompressed.
zip -r -0 ../unsigned_unaligned.apk \
    resources.arsc \
    $(find lib -name "*.so" 2>/dev/null) \
    2>/dev/null || true

# Add everything else with compression
zip -r ../unsigned_unaligned.apk . \
    --exclude "resources.arsc" \
    --exclude "lib/*" \
    2>/dev/null || true
cd ..

# ── zipalign ─────────────────────────────────────────────────────────────────
info "Running zipalign..."
zipalign -v -p 4 unsigned_unaligned.apk unsigned_aligned.apk
rm -f unsigned_unaligned.apk

# ── apksigner ────────────────────────────────────────────────────────────────
info "Signing APK with apksigner..."
cd "$OLDPWD"  # back to original dir

apksigner sign \
    --ks "$KEYSTORE" \
    --ks-key-alias "$KEY_ALIAS" \
    --ks-pass "pass:$STOREPASS" \
    --key-pass "pass:$KEYPASS" \
    --out "$OUTPUT_APK" \
    "$WORK_DIR/unsigned_aligned.apk"

# ── Verify ───────────────────────────────────────────────────────────────────
info "Verifying signature..."
apksigner verify --verbose "$OUTPUT_APK" 2>&1 | grep -E "Verified|error|warning" || true

APK_SIZE=$(du -sh "$OUTPUT_APK" | cut -f1)
info ""
info "✓ Done!"
info "  Output APK : $OUTPUT_APK  ($APK_SIZE)"
info "  Signed with: $KEYSTORE  (alias: $KEY_ALIAS)"
info ""
info "Install with:"
info "  adb install -r $OUTPUT_APK"
