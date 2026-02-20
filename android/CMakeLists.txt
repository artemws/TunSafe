# CMakeLists.txt — Android NDK build for libnative-lib.so
#
# Place this file at:
#   <repo_root>/android/CMakeLists.txt
#
# The C++ source tree is expected one level up (../../ from this file).
# Adjust TUNSAFE_ROOT if your layout differs.
#
# Supported ABIs: arm64-v8a, armeabi-v7a, x86_64, x86
# Min API: 21 (arm64-v8a / x86_64)  |  19 (armeabi-v7a / x86)

cmake_minimum_required(VERSION 3.22)
project(tunsafe_native VERSION 1.0 LANGUAGES CXX C ASM)

# ── Paths ─────────────────────────────────────────────────────────────────────
# Assumes this CMakeLists.txt lives in  <repo>/android/
# and the TunSafe C++ sources are in   <repo>/
set(TUNSAFE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

# ── Compiler flags ────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Common flags
set(COMMON_FLAGS
    -O2
    -DNDEBUG
    -DOS_ANDROID=1
    -DWITH_NETWORK_BSD=1
    -DCHACHA20_WITH_ASM=0
    -DBLAKE2S_WITH_ASM=0
    -fPIC
    -fvisibility=hidden
    -Wall
    -Wno-unused-parameter
    -Wno-missing-field-initializers
)

# ABI-specific flags
if(ANDROID_ABI STREQUAL "armeabi-v7a")
    list(APPEND COMMON_FLAGS -mfpu=neon -march=armv7-a+fp)
endif()

# ── Source files ──────────────────────────────────────────────────────────────
set(TUNSAFE_SOURCES
    # Android JNI bridge (this directory)
    "${CMAKE_CURRENT_SOURCE_DIR}/tunsafe_jni.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tunsafe_android.cpp"

    # TunSafe core (amalgamated — compiles everything in one shot)
    "${TUNSAFE_ROOT}/tunsafe_amalgam.cpp"

    # BSD/Linux network backend (used on Android)
    "${TUNSAFE_ROOT}/network_bsd.cpp"
    "${TUNSAFE_ROOT}/network_bsd_mt.cpp"
    "${TUNSAFE_ROOT}/network_common.cpp"
)

# ── Library target ────────────────────────────────────────────────────────────
add_library(native-lib SHARED ${TUNSAFE_SOURCES})

target_include_directories(native-lib PRIVATE
    "${TUNSAFE_ROOT}"
    "${TUNSAFE_ROOT}/crypto"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_compile_options(native-lib PRIVATE ${COMMON_FLAGS})

target_compile_definitions(native-lib PRIVATE
    # Tell tunsafe_amalgam / network_bsd to use our Platform* hooks
    # instead of the default POSIX implementations.
    TUNSAFE_ANDROID_PLATFORM_HOOKS=1
)

target_link_libraries(native-lib
    android
    log
    # pthread and dl are provided by the NDK's libc on modern API levels
)

# Strip in release builds (CMake does this automatically for SHARED libs
# when CMAKE_BUILD_TYPE=Release, but be explicit for CI)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET native-lib POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-unneeded
                $<TARGET_FILE:native-lib>
        COMMENT "Stripping native-lib.so"
    )
endif()

# ── Print build summary ───────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "=== TunSafe Android NDK build ===")
message(STATUS "  ABI          : ${ANDROID_ABI}")
message(STATUS "  API level    : ${ANDROID_PLATFORM}")
message(STATUS "  NDK          : ${ANDROID_NDK}")
message(STATUS "  TunSafe root : ${TUNSAFE_ROOT}")
message(STATUS "=================================")
message(STATUS "")
