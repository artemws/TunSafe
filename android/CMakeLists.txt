cmake_minimum_required(VERSION 3.18)
project(tunsafe-android)

# ──────────────────────────────────────────────────────────────
# Все исходники берутся из корня репо (родительская папка android/)
# CMake вызывается с -S android, поэтому CMAKE_CURRENT_SOURCE_DIR = android/
# а корень репо = ${CMAKE_CURRENT_SOURCE_DIR}/..
# ──────────────────────────────────────────────────────────────
set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Core sources — те же что в tunsafe_amalgam.cpp, но разбитые по файлам
# чтобы NDK/CMake мог их скомпилировать нормально
set(CORE_SOURCES
    ${ROOT}/wireguard.cpp
    ${ROOT}/wireguard_proto.cpp
    ${ROOT}/wireguard_config.cpp
    ${ROOT}/util.cpp
    ${ROOT}/tunsafe_threading.cpp
    ${ROOT}/tunsafe_cpu.cpp
    ${ROOT}/ip_to_peer_map.cpp
    ${ROOT}/tunsafe_ipaddr.cpp
    ${ROOT}/network_common.cpp
    ${ROOT}/network_bsd.cpp
    ${ROOT}/tunsafe_bsd.cpp
    ${ROOT}/crypto/curve25519/curve25519-donna.cpp
    ${ROOT}/crypto/chacha20poly1305.cpp
    ${ROOT}/crypto/blake2s/blake2s.cpp
    ${ROOT}/crypto/siphash/siphash.cpp
    ${ROOT}/crypto/aesgcm/aesgcm.cpp
    ${ROOT}/crypto/sha/sha1.cpp
    # Android JNI bridge (этот файл)
    ${CMAKE_CURRENT_SOURCE_DIR}/network_android.cpp
)

add_library(native-lib SHARED ${CORE_SOURCES})

target_include_directories(native-lib PRIVATE ${ROOT})

target_compile_options(native-lib PRIVATE
    -std=c++14
    -O2
    -DNDEBUG
    -DWITH_NETWORK_BSD=1
    # Отключаем ASM — нет arm64-linux ASM файлов для chacha20/poly1305
    -DCHACHA20_WITH_ASM=0
    -DBLAKE2S_WITH_ASM=0
    # Не компилируем tunsafe_wg_plugin как отдельный TU (он только для amalgam)
    -DTUNSAFE_NO_PLUGIN=1
    -fexceptions
    -frtti
    -Wall
    -Wno-unused-result
)

target_link_libraries(native-lib
    log        # android/log.h → __android_log_print
    android    # ANativeWindow и др. (на всякий случай)
)
