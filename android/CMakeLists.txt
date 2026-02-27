cmake_minimum_required(VERSION 3.18)
project(tunsafe-android)

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

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
    ${ROOT}/tunsafe_wg_plugin.cpp
    ${ROOT}/crypto/curve25519/curve25519-donna.cpp
    ${ROOT}/crypto/chacha20poly1305.cpp
    ${ROOT}/crypto/blake2s/blake2s.cpp
    ${ROOT}/crypto/siphash/siphash.cpp
    ${ROOT}/crypto/aesgcm/aesgcm.cpp
    ${ROOT}/crypto/sha/sha1.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/network_android.cpp
    ${ROOT}/wireguard_config_ext.cpp
)

add_library(tunsafe SHARED ${CORE_SOURCES})

target_include_directories(tunsafe PRIVATE ${ROOT})

target_compile_options(tunsafe PRIVATE
    -std=c++14
    -O2
    -DNDEBUG
    -DWITH_NETWORK_BSD=1
    -DCHACHA20_WITH_ASM=0
    -DBLAKE2S_WITH_ASM=0
    -fexceptions
    -frtti
    -Wall
    -Wno-unused-result
)

target_link_libraries(tunsafe
    log
    android
)
