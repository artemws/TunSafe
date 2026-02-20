# CMakeLists.txt — Android NDK build for libnative-lib.so
#
# Place at: <repo>/android/CMakeLists.txt
# Source tree expected at: <repo>/  (one level up)
#
# KEY POINT: We do NOT use tunsafe_amalgam.cpp because it includes
# tunsafe_bsd.cpp, benchmark.cpp and ts.cpp which are not Android-compatible.
# Instead we list only the files that work on Android.

cmake_minimum_required(VERSION 3.22)
project(tunsafe_native VERSION 1.0 LANGUAGES CXX C)

set(TUNSAFE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Compiler flags ────────────────────────────────────────────────────────────
set(COMMON_FLAGS
    -O2 -DNDEBUG
    -DANDROID=1
    -DOS_ANDROID=1
    -DWITH_NETWORK_BSD=1
    -DCHACHA20_WITH_ASM=0
    -DBLAKE2S_WITH_ASM=0
    -fPIC
    -fvisibility=hidden
    -Wno-unused-parameter
    -Wno-missing-field-initializers
    # Suppress noisy-but-harmless warnings from TunSafe sources
    -Wno-unused-result
)

if(ANDROID_ABI STREQUAL "armeabi-v7a")
    list(APPEND COMMON_FLAGS -mfpu=neon -march=armv7-a+fp)
endif()

# ── Android-compatible WireGuard core sources ─────────────────────────────────
# Equivalent to tunsafe_amalgam.cpp MINUS the non-Android files:
#   - benchmark.cpp       (uses LARGE_INTEGER, Windows/Linux only)
#   - tunsafe_bsd.cpp     (uses open_tun, GetDefaultRoute — no Android impl)
#   - ts.cpp              (CLI main, not needed in .so)
#   - network_bsd.cpp     (included via TUNSAFE_ROOT — keep it; it has Android path)

set(CORE_SOURCES
    "${TUNSAFE_ROOT}/wireguard.cpp"
    "${TUNSAFE_ROOT}/wireguard_proto.cpp"
    "${TUNSAFE_ROOT}/wireguard_config.cpp"
    "${TUNSAFE_ROOT}/tunsafe_wg_plugin.cpp"
    "${TUNSAFE_ROOT}/util.cpp"
    "${TUNSAFE_ROOT}/tunsafe_threading.cpp"
    "${TUNSAFE_ROOT}/tunsafe_cpu.cpp"
    "${TUNSAFE_ROOT}/ip_to_peer_map.cpp"
    "${TUNSAFE_ROOT}/tunsafe_ipaddr.cpp"
    "${TUNSAFE_ROOT}/crypto/curve25519/curve25519-donna.cpp"
    "${TUNSAFE_ROOT}/crypto/chacha20poly1305.cpp"
    "${TUNSAFE_ROOT}/crypto/blake2s/blake2s.cpp"
    "${TUNSAFE_ROOT}/crypto/siphash/siphash.cpp"
    "${TUNSAFE_ROOT}/crypto/aesgcm/aesgcm.cpp"
    "${TUNSAFE_ROOT}/crypto/sha/sha1.cpp"
    "${TUNSAFE_ROOT}/network_common.cpp"
    "${TUNSAFE_ROOT}/network_bsd.cpp"
    # Android JNI bridge and platform glue (this directory)
    "${CMAKE_CURRENT_SOURCE_DIR}/tunsafe_jni.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tunsafe_android.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/network_android.cpp"
)

# ── Library ───────────────────────────────────────────────────────────────────
add_library(native-lib SHARED ${CORE_SOURCES})

target_include_directories(native-lib PRIVATE
    "${TUNSAFE_ROOT}"
    "${TUNSAFE_ROOT}/crypto"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_compile_options(native-lib PRIVATE ${COMMON_FLAGS})

target_link_libraries(native-lib android log)

# Strip in release
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET native-lib POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:native-lib>
        COMMENT "Stripping native-lib.so"
    )
endif()

message(STATUS "TunSafe Android NDK: ABI=${ANDROID_ABI} API=${ANDROID_PLATFORM}")
